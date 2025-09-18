
import './index.css';

import { render } from 'preact'
import { useComputed, useSignal } from '@preact/signals';
import { Show } from '@preact/signals/utils';
import { retry, uint8ArrayToHex } from './utils';

render(<Challenge />, document.getElementById('pingoo-captcha')!)

type ChallengeInitApiResponse = {
  challenge: string,
  difficulty: number,
}

type ChallengeVerifyInput = {
  nonce: string,
  hash: string,
}

export function Challenge () {
  const domain = window.location.hostname;
  // let checkbox = signal(false);
  let checkboxLoading = useSignal(false);
  let verified = useSignal(false);
  let error = useSignal(false);

  let message = useComputed(() => {
    if (verified.value) {
      return 'Success!';
    } else if (checkboxLoading.value) {
      return 'Verifying...';
    }
    return 'Click on the checkbox';
  })

  async function onCheckboxClicked(event?: MouseEvent) {
    // prevent the checkbox from becoming checked
    event?.preventDefault();

    if (checkboxLoading.value || verified.value) {
      return;
    }

    error.value = false;
    checkboxLoading.value = true;

    try {
      const proofOfWorkSettings: ChallengeInitApiResponse = await retry(async () => {
        const initRes = await fetch('/__pingoo/captcha/api/init');
        if (initRes.status !== 200) {
          throw new Error(await initRes.text())
        }
        return await initRes.json();
      }, { delay: 200 });

      const proofOfWorkResult: ChallengeVerifyInput = await proofOfWork(proofOfWorkSettings.challenge, proofOfWorkSettings.difficulty);
      // const proofOfWorkResult: ChallengeVerifyInput = await proofOfWork('/__pingoo/captcha/api/verify', 4);
      // console.log(proofOfWorkResult);

      const verifyRes = await fetch('/__pingoo/captcha/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(proofOfWorkResult),
      });

      checkboxLoading.value = false;

      // if the challenge has been successfully verified by the server, show it
      if (verifyRes.status === 200) {
          verified.value = true;
      }

      // reload the page to allow access (or redo the challenge if verification has failed)
      setTimeout(() => location.reload(), 500);
    } catch (err: any) {
        console.error(err);
        error.value = true;
        checkboxLoading.value = false;
    }

    return;
  }

  return (
    <div className="h-full w-full flex justify-center">
      <div className="flex flex-col w-xl h-fit px-5 py-5 -mt-[20vh] space-y-8">

        <h1 className="text-2xl font-bold">{ domain }</h1>

        <h2 className="text-xl font-medium">
          Verify you are human by completing the action below.
        </h2>

        <div className="flex flex-col w-fit border rounded-md p-5 text-md items-center">
          <div className="flex items-center w-full">
            {!checkboxLoading.value &&
              <input type="checkbox" checked={verified.value} readOnly={verified.value} onClick={onCheckboxClicked}
                className="w-8 h-8 cursor-pointer text-blue-600 bg-gray-100 border-gray-300 rounded dark:bg-gray-700 dark:border-gray-600"
              />
            }
            <Show when={checkboxLoading}>
              <Loader className="h-8 w-8 text-gray-500 dark:text-gray-100" />
            </Show>
            <p className="ml-4">{message}</p>
          </div>
        </div>

        {error.value && <p className="font-medium text-red-500">
          Oops! Something went wrong. Please reload the page and ensure that your cookies are enabled.
        </p>}

      </div>
    </div>
  )
}

function Loader({ className }: { className: string}) {
  return (
    <div className={className}>
      <svg class="animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
    </div>
  )
}


export type ProofOfWorkResult = {
  nonce: string,
  hash: string,
}

export async function proofOfWork(challenge: string, difficulty: number): Promise<ProofOfWorkResult> {
    let nonce = 0;
    let hash = '';
    const target = '0'.repeat(difficulty); // Create a target string with 'difficulty' number of zeros

    do {
        nonce++;
        hash = uint8ArrayToHex(new Uint8Array(await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(challenge+nonce))));
    } while (hash.substring(0, difficulty) !== target);

    return { nonce: nonce.toString(10), hash };
}

