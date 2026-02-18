import {
  encodeTicket,
  encodeTicketToBytes,
  extractSignedData,
} from "dosipas-ts";
import type { UicBarcodeTicketInput, RailTicketInput } from "dosipas-ts";
import { signWithKms } from "./kms.js";

/** OID for EC key on P-256 curve */
const EC_P256_KEY_ALG = "1.2.840.10045.3.1.7";
/** OID for ECDSA with SHA-256 signing */
const ECDSA_SHA256_SIGNING_ALG = "1.2.840.10045.4.3.2";

export interface IssueRequest {
  /** Base64-encoded level 2 public key (raw EC point or SPKI DER) */
  level2PublicKey: string;
  /** Level 2 key algorithm OID (defaults to P-256) */
  level2KeyAlg?: string;
  /** Level 2 signing algorithm OID (defaults to ECDSA SHA-256) */
  level2SigningAlg?: string;
  /** Security provider RICS code */
  securityProviderNum?: number;
  /** Key ID for the level 1 key */
  keyId?: number;
  /** Header version (1 or 2, defaults to 2) */
  headerVersion?: number;
  /** FCB version (1, 2 or 3, defaults to 2) */
  fcbVersion?: number;
  /** Rail ticket data to encode */
  railTicket: RailTicketInput;
}

export interface IssueResponse {
  /** Hex-encoded signed DOSIPAS barcode (level 1 signed, no level 2 signature) */
  barcode: string;
}

/**
 * Issue a DOSIPAS barcode with level 1 signed by GCP KMS HSM.
 *
 * Two-pass encoding:
 * 1. Encode with a placeholder level1Signature to produce the barcode structure
 * 2. Extract level1DataBytes from the encoded barcode
 * 3. Sign level1DataBytes with KMS (ECDSA P-256 SHA-256)
 * 4. Re-encode with the real level1Signature
 */
export async function issueDosipas(req: IssueRequest): Promise<IssueResponse> {
  const level2PublicKey = new Uint8Array(
    Buffer.from(req.level2PublicKey, "base64"),
  );

  const baseInput: UicBarcodeTicketInput = {
    headerVersion: req.headerVersion ?? 2,
    fcbVersion: req.fcbVersion ?? 2,
    securityProviderNum: req.securityProviderNum,
    keyId: req.keyId,
    level1KeyAlg: EC_P256_KEY_ALG,
    level1SigningAlg: ECDSA_SHA256_SIGNING_ALG,
    level2KeyAlg: req.level2KeyAlg ?? EC_P256_KEY_ALG,
    level2SigningAlg: req.level2SigningAlg ?? ECDSA_SHA256_SIGNING_ALG,
    level2PublicKey,
    railTicket: req.railTicket,
  };

  // Pass 1: encode with a dummy level1Signature to get the structure
  const dummySignature = new Uint8Array(72); // max DER ECDSA P-256 sig size
  const pass1Input: UicBarcodeTicketInput = {
    ...baseInput,
    level1Signature: dummySignature,
  };
  const pass1Bytes = encodeTicketToBytes(pass1Input);

  // Extract the level1Data bytes (what the level1Signature covers)
  const { level1DataBytes } = extractSignedData(pass1Bytes);

  // Sign level1DataBytes with GCP KMS HSM
  const level1Signature = await signWithKms(level1DataBytes);

  // Pass 2: re-encode with the real level1Signature
  const finalInput: UicBarcodeTicketInput = {
    ...baseInput,
    level1Signature,
  };
  const barcode = encodeTicket(finalInput);

  return { barcode };
}
