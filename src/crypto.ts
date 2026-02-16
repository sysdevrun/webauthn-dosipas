/** Generate an ECDSA P-256 key pair and export the private key as PKCS8 DER bytes. */
export async function generatePrivateKey(): Promise<Uint8Array> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  return new Uint8Array(pkcs8);
}

/** Convert raw bytes to a hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert raw bytes to a PEM-encoded PKCS8 private key string. */
export function bytesToPem(bytes: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...bytes));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
}
