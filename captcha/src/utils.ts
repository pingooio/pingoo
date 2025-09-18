export async function retry<T>(
    fn: () => Promise<T>,
    options?: { attempts?: number; delay?: number }
): Promise<T> {
    const { attempts = 3, delay = 100 } = options || {};

    for (let i = 0; i < attempts; i++) {
        try {
            return await fn();
        } catch (error) {
            if (i < attempts - 1) {
                await new Promise(resolve => setTimeout(resolve, delay));
            } else {
                // rethrow the last error if all attempts fail
                throw error;
            }
        }
    }

    // fallback error
    throw new Error('this should never be reached');
}

export function uint8ArrayToHex(data: Uint8Array) {
  let hexString = '';
  for (let i = 0; i < data.length; i++) {
    // convert each byte to hex and pad with zeros
    hexString += data[i].toString(16).padStart(2, '0');
  }

  return hexString;
}

export function uint8ArrayTobase64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data));
}

export function base64ToUint8Array(base64: string) {
  var binaryString = atob(base64);
  var bytes = new Uint8Array(binaryString.length);
  for (var i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}
