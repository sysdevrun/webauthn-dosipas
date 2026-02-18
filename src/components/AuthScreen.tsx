import { useState } from "react";
import { register, authenticate } from "../lib/webauthn";

interface AuthScreenProps {
  onAuthenticated: (params: {
    email: string;
    prfOutput: Uint8Array;
    credentialId: Uint8Array;
    mode: "register" | "signin";
  }) => void;
  onError: (error: string) => void;
}

export default function AuthScreen({
  onAuthenticated,
  onError,
}: AuthScreenProps) {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  const handleRegister = async () => {
    if (!email.trim()) {
      onError("Please enter an email address.");
      return;
    }
    setLoading(true);
    try {
      const result = await register(email.trim());
      if (!result.prfSupported) {
        onError(
          "Your authenticator does not support the PRF extension. " +
            "Try a FIDO2 security key or a platform authenticator with PRF support (Chrome 116+, Safari 18+).",
        );
        setLoading(false);
        return;
      }
      // Now authenticate to get PRF output
      const prfOutput = await authenticate(result.credentialId);
      onAuthenticated({
        email: email.trim(),
        prfOutput,
        credentialId: result.credentialId,
        mode: "register",
      });
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleSignIn = async () => {
    setLoading(true);
    try {
      // Discoverable credential — no credential ID needed
      const prfOutput = await authenticate();
      onAuthenticated({
        email: "(discoverable)",
        prfOutput,
        credentialId: new Uint8Array(0),
        mode: "signin",
      });
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="bg-gray-900 rounded-lg p-6 space-y-5 border border-gray-800">
      <h2 className="text-xl font-semibold">Authenticate</h2>
      <p className="text-gray-400 text-sm">
        Register a new passkey or sign in with an existing one. The PRF
        extension derives deterministic cryptographic keys from your
        authenticator.
      </p>

      <div className="space-y-3">
        <input
          type="email"
          placeholder="Email address"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={loading}
          className="w-full rounded-md bg-gray-800 border border-gray-700 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50"
        />
        <div className="flex gap-3">
          <button
            onClick={handleRegister}
            disabled={loading}
            className="flex-1 rounded-md bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 px-5 py-2.5 text-sm font-medium transition-colors cursor-pointer"
          >
            {loading ? "Working..." : "Register new passkey"}
          </button>
          <button
            onClick={handleSignIn}
            disabled={loading}
            className="flex-1 rounded-md bg-gray-700 hover:bg-gray-600 disabled:opacity-50 px-5 py-2.5 text-sm font-medium transition-colors cursor-pointer"
          >
            {loading ? "Working..." : "Sign in with passkey"}
          </button>
        </div>
      </div>
    </section>
  );
}
