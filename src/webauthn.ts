/**
 * WebAuthn helpers using the PRF extension to deterministically derive
 * an ECDSA P-256 private key from a credential secret + salt (ticket ID).
 *
 * PRF flow:
 *  1. Register: create a credential with `prf: {}` to enable the extension.
 *  2. Derive:   authenticate with `prf: { eval: { first: salt } }`.
 *               The authenticator returns 32 deterministic bytes.
 *               Same credential + same salt = same output every time.
 */

const RP_NAME = "WebAuthn PRF Key Derivation";

function rpId(): string {
  return window.location.hostname;
}

function randomChallenge(): BufferSource {
  return crypto.getRandomValues(new Uint8Array(32)) as BufferSource;
}

/** Register a new credential with PRF enabled. */
export async function register(
  username: string,
): Promise<void> {
  const createOptions: PublicKeyCredentialCreationOptions = {
    rp: { name: RP_NAME, id: rpId() },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)) as BufferSource,
      name: username,
      displayName: username,
    },
    challenge: randomChallenge(),
    pubKeyCredParams: [{ alg: -7, type: "public-key" }], // ES256
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
    extensions: {
      prf: {},
    },
  };

  const credential = (await navigator.credentials.create({
    publicKey: createOptions,
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error("Registration cancelled.");

  const extResults = credential.getClientExtensionResults() as Record<string, unknown>;
  const prfResult = extResults.prf as { enabled?: boolean } | undefined;
  if (!prfResult?.enabled) {
    throw new Error(
      "Your authenticator does not support the PRF extension. " +
        "Try a compatible security key or update Chrome.",
    );
  }
}

/**
 * Authenticate and evaluate PRF with the given salt.
 * Returns the raw 32-byte PRF output.
 */
export async function deriveWithPrf(
  salt: BufferSource,
): Promise<Uint8Array> {
  const getOptions: PublicKeyCredentialRequestOptions = {
    challenge: randomChallenge(),
    rpId: rpId(),
    userVerification: "required",
    extensions: {
      prf: {
        eval: { first: salt },
      },
    },
  };

  const assertion = (await navigator.credentials.get({
    publicKey: getOptions,
  })) as PublicKeyCredential | null;

  if (!assertion) throw new Error("Authentication cancelled.");

  const extResults = assertion.getClientExtensionResults() as Record<string, unknown>;
  const prfResult = extResults.prf as {
    results?: { first?: ArrayBuffer };
  } | undefined;

  if (!prfResult?.results?.first) {
    throw new Error(
      "PRF evaluation returned no result. " +
        "Make sure you registered with a PRF-capable credential.",
    );
  }

  return new Uint8Array(prfResult.results.first);
}
