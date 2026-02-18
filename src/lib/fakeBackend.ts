/**
 * Fake backend backed by localStorage.
 *
 * Stores payment records keyed by the JWK Thumbprint of the ECDSA public key.
 * This module simulates two REST endpoints:
 *   - POST /payments   → storePayment()
 *   - GET  /payments/:pubkey → lookupByPublicKey()
 *
 * All stored records can be enumerated for the debug/explorer UI.
 */

import { jwkThumbprint } from "./crypto";

const STORAGE_PREFIX = "dosipas:";

export interface PaymentRecord {
  paymentRef: string;
  paymentDate: string;
  ecdsaPublicKey: JsonWebKey;
  /** JWK thumbprint used as storage key */
  thumbprint: string;
}

/**
 * Store a payment record, keyed by the ECDSA public key thumbprint.
 * Returns the stored record (simulating a backend response).
 */
export async function storePayment(data: {
  paymentRef: string;
  paymentDate: string;
  ecdsaPublicKey: JsonWebKey;
}): Promise<PaymentRecord> {
  const thumbprint = await jwkThumbprint(data.ecdsaPublicKey);
  const record: PaymentRecord = { ...data, thumbprint };
  localStorage.setItem(
    STORAGE_PREFIX + thumbprint,
    JSON.stringify(record),
  );
  return record;
}

/**
 * Look up a payment record by ECDSA public key.
 * Returns null if not found.
 */
export async function lookupByPublicKey(
  ecdsaPublicKey: JsonWebKey,
): Promise<PaymentRecord | null> {
  const thumbprint = await jwkThumbprint(ecdsaPublicKey);
  const raw = localStorage.getItem(STORAGE_PREFIX + thumbprint);
  if (!raw) return null;
  return JSON.parse(raw) as PaymentRecord;
}

/**
 * List all stored payment records (for the backend explorer UI).
 */
export function listAllRecords(): PaymentRecord[] {
  const records: PaymentRecord[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith(STORAGE_PREFIX)) {
      try {
        records.push(JSON.parse(localStorage.getItem(key)!) as PaymentRecord);
      } catch {
        // skip malformed entries
      }
    }
  }
  return records;
}

/**
 * Delete a specific record by thumbprint (for debug UI).
 */
export function deleteRecord(thumbprint: string): void {
  localStorage.removeItem(STORAGE_PREFIX + thumbprint);
}

/**
 * Delete all dosipas records (for debug UI).
 */
export function clearAllRecords(): void {
  const keysToRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith(STORAGE_PREFIX)) {
      keysToRemove.push(key);
    }
  }
  keysToRemove.forEach((k) => localStorage.removeItem(k));
}
