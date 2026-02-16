/**
 * WebAuthn helpers using the largeBlob extension to store / retrieve
 * an ECDSA P-256 private key.
 *
 * Requirements:
 *  - A platform or roaming authenticator that supports the largeBlob extension.
 *  - The page must be served over HTTPS (or localhost).
 */

const RP_NAME = "WebAuthn Key Recovery Demo";

function rpId(): string {
  return window.location.hostname;
}

function randomChallenge(): BufferSource {
  return crypto.getRandomValues(new Uint8Array(32)) as BufferSource;
}

/**
 * Register a new credential **and** write the private key as a largeBlob.
 * `largeBlob: { support: "required" }` is passed during registration so the
 * ceremony fails if the authenticator doesn't support it.
 */
export async function register(
  username: string,
  privateKeyBytes: Uint8Array,
): Promise<{ credentialId: Uint8Array }> {
  // Step 1: create the credential with largeBlob support required
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
      largeBlob: { support: "required" },
    },
  };

  const credential = (await navigator.credentials.create({
    publicKey: createOptions,
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error("Registration cancelled");

  const extResults = credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    largeBlob?: { supported?: boolean };
  };
  if (!extResults.largeBlob?.supported) {
    throw new Error(
      "Authenticator does not support the largeBlob extension. " +
        "Please use a compatible security key or platform authenticator.",
    );
  }

  const credentialId = new Uint8Array(credential.rawId);

  // Step 2: immediately do an assertion to write the blob
  const getOptions: PublicKeyCredentialRequestOptions = {
    challenge: randomChallenge(),
    rpId: rpId(),
    allowCredentials: [
      { id: credentialId as BufferSource, type: "public-key" },
    ],
    userVerification: "required",
    extensions: {
      largeBlob: { write: privateKeyBytes as BufferSource },
    },
  };

  const assertion = (await navigator.credentials.get({
    publicKey: getOptions,
  })) as PublicKeyCredential | null;

  if (!assertion) throw new Error("Blob write assertion cancelled");

  const writeResults = assertion.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    largeBlob?: { written?: boolean };
  };
  if (!writeResults.largeBlob?.written) {
    throw new Error("Failed to write private key to authenticator largeBlob.");
  }

  return { credentialId };
}

/**
 * Authenticate with an existing credential and read back the largeBlob
 * containing the private key.
 */
export async function authenticate(): Promise<{
  privateKeyBytes: Uint8Array;
}> {
  const getOptions: PublicKeyCredentialRequestOptions = {
    challenge: randomChallenge(),
    rpId: rpId(),
    userVerification: "required",
    extensions: {
      largeBlob: { read: true },
    },
  };

  const assertion = (await navigator.credentials.get({
    publicKey: getOptions,
  })) as PublicKeyCredential | null;

  if (!assertion) throw new Error("Authentication cancelled");

  const extResults = assertion.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    largeBlob?: { blob?: ArrayBuffer };
  };
  if (!extResults.largeBlob?.blob) {
    throw new Error(
      "No largeBlob data returned. The authenticator may not contain a stored key for this credential.",
    );
  }

  return { privateKeyBytes: new Uint8Array(extResults.largeBlob.blob) };
}
