import { useState } from "react";
import { generatePrivateKey, bytesToHex, bytesToPem } from "./crypto";
import { register, authenticate } from "./webauthn";

type Status = "idle" | "loading" | "success" | "error";

function App() {
  const [username, setUsername] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState("");
  const [recoveredKeyHex, setRecoveredKeyHex] = useState("");
  const [recoveredKeyPem, setRecoveredKeyPem] = useState("");

  const handleRegister = async () => {
    if (!username.trim()) {
      setStatus("error");
      setMessage("Please enter a username.");
      return;
    }
    try {
      setStatus("loading");
      setMessage("Generating ECDSA P-256 private key...");
      const privateKeyBytes = await generatePrivateKey();

      setMessage("Registering with WebAuthn (largeBlob required)...");
      await register(username.trim(), privateKeyBytes);

      setStatus("success");
      setMessage(
        "Registration complete! Your private key has been stored in the authenticator's largeBlob. You can now recover it by signing in.",
      );
      setRecoveredKeyHex("");
      setRecoveredKeyPem("");
    } catch (err) {
      setStatus("error");
      setMessage(err instanceof Error ? err.message : String(err));
    }
  };

  const handleRecover = async () => {
    try {
      setStatus("loading");
      setMessage("Authenticating with WebAuthn to read largeBlob...");
      const { privateKeyBytes } = await authenticate();

      setRecoveredKeyHex(bytesToHex(privateKeyBytes));
      setRecoveredKeyPem(bytesToPem(privateKeyBytes));
      setStatus("success");
      setMessage("Private key recovered successfully!");
    } catch (err) {
      setStatus("error");
      setMessage(err instanceof Error ? err.message : String(err));
      setRecoveredKeyHex("");
      setRecoveredKeyPem("");
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex items-center justify-center p-4">
      <div className="w-full max-w-xl space-y-8">
        <header className="text-center space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">
            WebAuthn Key Recovery
          </h1>
          <p className="text-gray-400 text-sm">
            Generate an ECDSA P-256 private key, store it via WebAuthn
            largeBlob, and recover it later.
          </p>
        </header>

        {/* Register */}
        <section className="bg-gray-900 rounded-lg p-6 space-y-4 border border-gray-800">
          <h2 className="text-lg font-semibold">1. Register</h2>
          <p className="text-gray-400 text-sm">
            A new ECDSA P-256 private key will be generated and stored inside
            your authenticator's largeBlob during registration.
          </p>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-md bg-gray-800 border border-gray-700 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <button
            onClick={handleRegister}
            disabled={status === "loading"}
            className="w-full rounded-md bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 px-4 py-2 text-sm font-medium transition-colors cursor-pointer"
          >
            {status === "loading" ? "Working..." : "Generate Key & Register"}
          </button>
        </section>

        {/* Recover */}
        <section className="bg-gray-900 rounded-lg p-6 space-y-4 border border-gray-800">
          <h2 className="text-lg font-semibold">2. Recover Key</h2>
          <p className="text-gray-400 text-sm">
            Sign in with your existing WebAuthn credential to retrieve the
            private key from the largeBlob.
          </p>
          <button
            onClick={handleRecover}
            disabled={status === "loading"}
            className="w-full rounded-md bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 text-sm font-medium transition-colors cursor-pointer"
          >
            {status === "loading" ? "Working..." : "Sign In & Recover Key"}
          </button>
        </section>

        {/* Status */}
        {message && (
          <div
            className={`rounded-md p-4 text-sm ${
              status === "error"
                ? "bg-red-900/50 text-red-300 border border-red-800"
                : status === "success"
                  ? "bg-green-900/50 text-green-300 border border-green-800"
                  : "bg-blue-900/50 text-blue-300 border border-blue-800"
            }`}
          >
            {message}
          </div>
        )}

        {/* Recovered key display */}
        {recoveredKeyHex && (
          <section className="bg-gray-900 rounded-lg p-6 space-y-4 border border-gray-800">
            <h2 className="text-lg font-semibold text-emerald-400">
              Recovered Private Key
            </h2>

            <div>
              <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">
                Hex
              </h3>
              <pre className="bg-gray-800 rounded-md p-3 text-xs break-all whitespace-pre-wrap select-all">
                {recoveredKeyHex}
              </pre>
            </div>

            <div>
              <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">
                PEM (PKCS#8)
              </h3>
              <pre className="bg-gray-800 rounded-md p-3 text-xs break-all whitespace-pre-wrap select-all">
                {recoveredKeyPem}
              </pre>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

export default App;
