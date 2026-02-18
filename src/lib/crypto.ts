/**
 * Cryptographic utilities:
 * - HKDF derivation of AES-GCM-256 + ECDSA P-256 from PRF output
 * - Canonical JSON serialization (sorted keys)
 * - ECDSA signing with ASN.1 DER output
 * - Key import/export helpers
 */

// ---------------------------------------------------------------------------
// PKCS#8 DER prefix for EC P-256 private key (minimal, no public key field)
//
//   SEQUENCE {
//     INTEGER 0
//     SEQUENCE { OID ecPublicKey, OID secp256r1 }
//     OCTET STRING {
//       SEQUENCE { INTEGER 1, OCTET STRING(32) <scalar> }
//     }
//   }
// ---------------------------------------------------------------------------
const PKCS8_P256_PREFIX = new Uint8Array([
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
  0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
]);

// ---------------------------------------------------------------------------
// HKDF salt — deterministic, application-specific (not all-zeros)
// ---------------------------------------------------------------------------
const HKDF_SALT_INPUT = new TextEncoder().encode("dosipas-hkdf-salt-v1");

async function getHkdfSalt(): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest("SHA-256", HKDF_SALT_INPUT);
  return new Uint8Array(hash);
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

export interface DerivedKeys {
  aesKey: CryptoKey;
  ecdsaKeyPair: {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeyJwk: JsonWebKey;
  };
  /** Raw bytes used as ECDSA scalar (for debug display) */
  ecdsaScalarHex: string;
}

/**
 * Derive an AES-GCM-256 key and an ECDSA P-256 key pair from 32-byte PRF
 * output using HKDF with domain-separated info strings.
 */
export async function deriveKeys(prfOutput: Uint8Array): Promise<DerivedKeys> {
  const salt = await getHkdfSalt();

  // Import PRF output as HKDF key material
  const ikm = await crypto.subtle.importKey(
    "raw",
    prfOutput as BufferSource,
    "HKDF",
    false,
    ["deriveBits", "deriveKey"],
  );

  // --- AES-GCM-256 ---
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: new TextEncoder().encode("dosipas-aes-gcm") as BufferSource,
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  // --- ECDSA P-256 ---
  const ecdsaBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: new TextEncoder().encode("dosipas-ecdsa-p256") as BufferSource,
    },
    ikm,
    256,
  );
  const ecdsaScalar = new Uint8Array(ecdsaBits);

  // Build minimal PKCS#8 and import to get the full key pair
  const minimalDer = new Uint8Array(
    PKCS8_P256_PREFIX.length + ecdsaScalar.length,
  );
  minimalDer.set(PKCS8_P256_PREFIX);
  minimalDer.set(ecdsaScalar, PKCS8_P256_PREFIX.length);

  const ecdsaPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    minimalDer as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );

  // Export private as JWK to extract public coordinates, then re-import public
  const jwkPrivate = await crypto.subtle.exportKey("jwk", ecdsaPrivateKey);
  const publicKeyJwk: JsonWebKey = {
    kty: jwkPrivate.kty,
    crv: jwkPrivate.crv,
    x: jwkPrivate.x,
    y: jwkPrivate.y,
  };
  const ecdsaPublicKey = await crypto.subtle.importKey(
    "jwk",
    publicKeyJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );

  return {
    aesKey,
    ecdsaKeyPair: {
      privateKey: ecdsaPrivateKey,
      publicKey: ecdsaPublicKey,
      publicKeyJwk,
    },
    ecdsaScalarHex: bytesToHex(ecdsaScalar),
  };
}

// ---------------------------------------------------------------------------
// Canonical JSON — deterministic key ordering for signing
// ---------------------------------------------------------------------------

/**
 * Produce a canonical JSON string with keys sorted recursively.
 * This ensures the same logical object always produces the same bytes
 * for signature verification.
 */
export function canonicalJsonStringify(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  });
}

// ---------------------------------------------------------------------------
// ECDSA signing — P1363 → ASN.1 DER conversion
// ---------------------------------------------------------------------------

/**
 * Sign a payload string with ECDSA P-256 / SHA-256.
 * Returns the signature in ASN.1 DER format (base64url-encoded).
 */
export async function signPayload(
  privateKey: CryptoKey,
  payload: string,
): Promise<string> {
  const data = new TextEncoder().encode(payload);
  const p1363Sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data,
  );
  const derSig = p1363ToDer(new Uint8Array(p1363Sig));
  return base64urlEncode(derSig);
}

/**
 * Verify an ECDSA P-256 / SHA-256 signature (ASN.1 DER, base64url-encoded)
 * against a payload string.
 */
export async function verifySignature(
  publicKey: CryptoKey,
  payload: string,
  signatureB64u: string,
): Promise<boolean> {
  const derSig = base64urlDecode(signatureB64u);
  const p1363Sig = derToP1363(derSig);
  const data = new TextEncoder().encode(payload);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    p1363Sig as BufferSource,
    data,
  );
}

// ---------------------------------------------------------------------------
// P1363 ↔ ASN.1 DER conversion for ECDSA signatures
// ---------------------------------------------------------------------------

/** Convert IEEE P1363 (r||s, 64 bytes) to ASN.1 DER. */
function p1363ToDer(sig: Uint8Array): Uint8Array {
  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);
  const rDer = integerToDer(r);
  const sDer = integerToDer(s);
  const seqLen = rDer.length + sDer.length;
  const der = new Uint8Array(2 + seqLen);
  der[0] = 0x30; // SEQUENCE
  der[1] = seqLen;
  der.set(rDer, 2);
  der.set(sDer, 2 + rDer.length);
  return der;
}

/** Convert ASN.1 DER ECDSA signature to IEEE P1363 (r||s, 64 bytes). */
function derToP1363(der: Uint8Array): Uint8Array {
  // SEQUENCE { INTEGER r, INTEGER s }
  let offset = 2; // skip SEQUENCE tag + length
  const r = readDerInteger(der, offset);
  offset += 2 + der[offset + 1];
  const s = readDerInteger(der, offset);
  const out = new Uint8Array(64);
  out.set(padTo32(r), 0);
  out.set(padTo32(s), 32);
  return out;
}

/** Encode a big-endian unsigned integer as ASN.1 DER INTEGER. */
function integerToDer(val: Uint8Array): Uint8Array {
  // Strip leading zeros but keep at least one byte
  let start = 0;
  while (start < val.length - 1 && val[start] === 0) start++;
  const trimmed = val.slice(start);
  // If high bit is set, prepend a 0x00 byte (positive integer)
  const needsPad = trimmed[0] & 0x80;
  const len = trimmed.length + (needsPad ? 1 : 0);
  const out = new Uint8Array(2 + len);
  out[0] = 0x02; // INTEGER tag
  out[1] = len;
  if (needsPad) {
    out[2] = 0x00;
    out.set(trimmed, 3);
  } else {
    out.set(trimmed, 2);
  }
  return out;
}

/** Read a DER INTEGER at the given offset, return the raw value bytes. */
function readDerInteger(der: Uint8Array, offset: number): Uint8Array {
  // der[offset] = 0x02 (INTEGER tag), der[offset+1] = length
  const len = der[offset + 1];
  const value = der.slice(offset + 2, offset + 2 + len);
  // Strip leading zero padding
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  return value.slice(start);
}

/** Left-pad a byte array to exactly 32 bytes. */
function padTo32(val: Uint8Array): Uint8Array {
  if (val.length >= 32) return val.slice(val.length - 32);
  const out = new Uint8Array(32);
  out.set(val, 32 - val.length);
  return out;
}

// ---------------------------------------------------------------------------
// Encoding utilities
// ---------------------------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function base64urlEncode(bytes: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(str: string): Uint8Array {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) % 4;
  const padded = b64 + "=".repeat(pad);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Compute the JWK Thumbprint (SHA-256) of a public key — used as storage key. */
export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  // RFC 7638: canonical JSON with required members for EC keys, sorted
  const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(jwk.kty)},"x":${JSON.stringify(jwk.x)},"y":${JSON.stringify(jwk.y)}}`;
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical),
  );
  return base64urlEncode(new Uint8Array(hash));
}
