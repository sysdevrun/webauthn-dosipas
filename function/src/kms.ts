import { KeyManagementServiceClient } from "@google-cloud/kms";
import { createHash, createPublicKey } from "node:crypto";

const client = new KeyManagementServiceClient();

function getKeyVersionName(): string {
  const project = process.env.GCP_PROJECT;
  const location = process.env.KMS_LOCATION ?? "europe-west1";
  const keyring = process.env.KMS_KEYRING ?? "dosipas-keyring";
  const key = process.env.KMS_KEY ?? "dosipas-level1-signing";
  const version = process.env.KMS_KEY_VERSION ?? "1";

  if (!project) {
    throw new Error("GCP_PROJECT environment variable is required");
  }

  return `projects/${project}/locations/${location}/keyRings/${keyring}/cryptoKeys/${key}/cryptoKeyVersions/${version}`;
}

/**
 * Sign data using the GCP KMS HSM key (ECDSA P-256 SHA-256).
 * KMS expects a pre-hashed digest for asymmetric signing.
 * Returns the DER-encoded ECDSA signature.
 */
export async function signWithKms(data: Uint8Array): Promise<Uint8Array> {
  const digest = createHash("sha256").update(data).digest();

  const [response] = await client.asymmetricSign({
    name: getKeyVersionName(),
    digest: { sha256: digest },
  });

  if (!response.signature) {
    throw new Error("KMS asymmetricSign returned no signature");
  }

  // response.signature is a Buffer (DER-encoded ECDSA signature)
  return new Uint8Array(
    response.signature instanceof Uint8Array
      ? response.signature
      : Buffer.from(response.signature as string, "base64"),
  );
}

/**
 * Retrieve the public key from GCP KMS in SPKI DER format.
 */
export async function getLevel1PublicKey(): Promise<Uint8Array> {
  const [publicKey] = await client.getPublicKey({
    name: getKeyVersionName(),
  });

  if (!publicKey.pem) {
    throw new Error("KMS getPublicKey returned no PEM");
  }

  const keyObj = createPublicKey(publicKey.pem);
  const der = keyObj.export({ type: "spki", format: "der" });
  return new Uint8Array(der);
}
