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

export function uint8ArrayToHex(data: Uint8Array) {
  let hexString = '';
  for (let i = 0; i < data.length; i++) {
    // convert each byte to hex and pad with zeros
    hexString += data[i].toString(16).padStart(2, '0');
  }

  return hexString;
}
