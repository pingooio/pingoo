import { uint8ArrayToHex } from "./buffer";

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

// function countLeadingZeroBytes(data: Uint8Array) {
//     // Find the index of the first non-zero byte
//     const firstNonZeroIndex = Array.from(data).findIndex(byte => byte !== 0);

//     // If all bytes are zero, return the length of the array
//     return firstNonZeroIndex === -1 ? data.length : firstNonZeroIndex;
// }

