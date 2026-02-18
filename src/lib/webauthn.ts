/**
 * WebAuthn helpers using the PRF extension.
 *
 * Flow:
 *  1. register(email): create a discoverable credential with PRF enabled.
 *  2. authenticate(credentialId?): authenticate + evaluate PRF → 32 bytes.
 *
 * The PRF salt is a fixed application-specific value so that the same
 * credential always produces the same 32-byte output (one credential =
 * one identity = one deterministic key set).
 */

const RP_NAME = "DOSIPAS Ticket";

function rpId(): string {
  return window.location.hostname;
}

function randomChallenge(): BufferSource {
  return crypto.getRandomValues(new Uint8Array(32)) as BufferSource;
}

/** Fixed PRF salt — SHA-256("dosipas-prf-v1") */
async function prfSalt(): Promise<Uint8Array> {
  const input = new TextEncoder().encode("dosipas-prf-v1");
  const hash = await crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(hash);
}

export interface RegisterResult {
  credentialId: Uint8Array;
  prfSupported: boolean;
}

/**
 * Register a new discoverable credential with PRF enabled.
 * Returns the credential ID and whether PRF is supported.
 */
export async function register(email: string): Promise<RegisterResult> {
  const createOptions: PublicKeyCredentialCreationOptions = {
    rp: { name: RP_NAME, id: rpId() },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)) as BufferSource,
      name: email,
      displayName: email,
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

  const extResults = credential.getClientExtensionResults() as Record<
    string,
    unknown
  >;
  const prfResult = extResults.prf as { enabled?: boolean } | undefined;

  return {
    credentialId: new Uint8Array(credential.rawId),
    prfSupported: prfResult?.enabled === true,
  };
}

/**
 * Authenticate with PRF evaluation using the fixed application salt.
 * If credentialId is provided, scopes to that credential.
 * Returns the raw 32-byte PRF output.
 */
export async function authenticate(
  credentialId?: Uint8Array,
): Promise<Uint8Array> {
  const salt = await prfSalt();

  const getOptions: PublicKeyCredentialRequestOptions = {
    challenge: randomChallenge(),
    rpId: rpId(),
    userVerification: "required",
    extensions: {
      prf: {
        eval: { first: salt as BufferSource },
      },
    },
    ...(credentialId && {
      allowCredentials: [
        { id: credentialId as BufferSource, type: "public-key" as const },
      ],
    }),
  };

  const assertion = (await navigator.credentials.get({
    publicKey: getOptions,
  })) as PublicKeyCredential | null;

  if (!assertion) throw new Error("Authentication cancelled.");

  const extResults = assertion.getClientExtensionResults() as Record<
    string,
    unknown
  >;
  const prfResult = extResults.prf as {
    results?: { first?: ArrayBuffer };
  } | undefined;

  if (!prfResult?.results?.first) {
    throw new Error(
      "PRF evaluation returned no result. " +
        "Make sure you registered with a PRF-capable authenticator.",
    );
  }

  return new Uint8Array(prfResult.results.first);
}
