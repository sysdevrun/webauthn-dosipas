/** Hash a ticket ID string into a 32-byte salt via SHA-256. */
export async function ticketIdToSalt(ticketId: string): Promise<Uint8Array> {
  const encoded = new TextEncoder().encode(ticketId);
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  return new Uint8Array(hash);
}

/**
 * Import 32 raw PRF bytes as an ECDSA P-256 private key via Web Crypto,
 * then re-export as PKCS#8 DER.  This guarantees the scalar is valid and
 * the DER encoding includes the computed public point.
 */
export async function prfBytesToPkcs8(raw: Uint8Array): Promise<Uint8Array> {
  const minimalDer = buildMinimalPkcs8(raw);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    minimalDer as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
  const fullDer = await crypto.subtle.exportKey("pkcs8", key);
  return new Uint8Array(fullDer);
}

/**
 * PKCS#8 DER prefix for an EC P-256 private key (ECPrivateKey without
 * the optional public key field).
 *
 *   SEQUENCE {
 *     INTEGER 0
 *     SEQUENCE { OID ecPublicKey, OID secp256r1 }
 *     OCTET STRING {
 *       SEQUENCE { INTEGER 1, OCTET STRING(32) <scalar> }
 *     }
 *   }
 */
const PKCS8_P256_PREFIX = new Uint8Array([
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
  0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
]);

function buildMinimalPkcs8(scalar: Uint8Array): Uint8Array {
  const der = new Uint8Array(PKCS8_P256_PREFIX.length + scalar.length);
  der.set(PKCS8_P256_PREFIX);
  der.set(scalar, PKCS8_P256_PREFIX.length);
  return der;
}

/** Convert raw bytes to a hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert DER bytes to a PEM-encoded private key string. */
export function bytesToPem(der: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...der));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
}
