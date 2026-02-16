import { useState } from "react";
import { ticketIdToSalt, buildPkcs8, bytesToHex, bytesToPem } from "./crypto";
import { register, deriveWithPrf } from "./webauthn";

type Status = "idle" | "loading" | "success" | "error";

function App() {
  const [username, setUsername] = useState("");
  const [ticketId, setTicketId] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState("");
  const [registered, setRegistered] = useState(false);
  const [derivedKeyHex, setDerivedKeyHex] = useState("");
  const [derivedKeyPem, setDerivedKeyPem] = useState("");
  const [usedTicketId, setUsedTicketId] = useState("");

  const handleRegister = async () => {
    if (!username.trim()) {
      setStatus("error");
      setMessage("Please enter a username.");
      return;
    }
    try {
      setStatus("loading");
      setMessage("Registering credential with PRF support...");
      await register(username.trim());
      setRegistered(true);
      setStatus("success");
      setMessage(
        "Credential registered with PRF enabled! You can now derive keys.",
      );
    } catch (err) {
      setStatus("error");
      setMessage(err instanceof Error ? err.message : String(err));
    }
  };

  const handleDerive = async () => {
    if (!ticketId.trim()) {
      setStatus("error");
      setMessage("Please enter a Ticket ID to use as salt.");
      return;
    }
    try {
      setStatus("loading");
      setMessage("Authenticating and evaluating PRF...");
      const salt = await ticketIdToSalt(ticketId.trim());
      const prfOutput = await deriveWithPrf(salt as BufferSource);

      const pkcs8 = buildPkcs8(prfOutput);
      setDerivedKeyHex(bytesToHex(prfOutput));
      setDerivedKeyPem(bytesToPem(pkcs8));
      setUsedTicketId(ticketId.trim());
      setStatus("success");
      setMessage("Private key derived successfully!");
    } catch (err) {
      setStatus("error");
      setMessage(err instanceof Error ? err.message : String(err));
      setDerivedKeyHex("");
      setDerivedKeyPem("");
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex items-center justify-center p-4">
      <div className="w-full max-w-2xl space-y-6">
        {/* Header */}
        <header className="text-center space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">
            WebAuthn PRF Key Derivation
          </h1>
          <p className="text-gray-400 text-sm max-w-lg mx-auto">
            Derive deterministic ECDSA P-256 private keys from a WebAuthn
            credential using the PRF extension.
          </p>
        </header>

        {/* How PRF works */}
        <section className="bg-gray-900 rounded-lg p-6 border border-gray-800 space-y-4">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
            How it works
          </h2>

          {/* Diagram */}
          <div className="flex flex-col items-center gap-1 py-2 text-sm font-mono">
            <div className="flex items-center gap-3">
              <span className="bg-indigo-900/60 text-indigo-300 border border-indigo-700 rounded px-3 py-1">
                Credential Secret
              </span>
              <span className="text-gray-500">+</span>
              <span className="bg-amber-900/60 text-amber-300 border border-amber-700 rounded px-3 py-1">
                Ticket ID (salt)
              </span>
            </div>
            <span className="text-gray-600">|</span>
            <span className="bg-gray-800 text-gray-300 border border-gray-700 rounded px-3 py-1">
              PRF( secret, salt )
            </span>
            <span className="text-gray-600">|</span>
            <span className="bg-emerald-900/60 text-emerald-300 border border-emerald-700 rounded px-3 py-1">
              32 bytes &rarr; ECDSA P-256 Private Key
            </span>
          </div>

          <ul className="text-gray-400 text-sm space-y-1 list-disc list-inside">
            <li>
              <strong className="text-gray-300">PRF</strong> is a WebAuthn
              extension that evaluates a pseudo-random function inside your
              authenticator.
            </li>
            <li>
              Your authenticator holds a <strong className="text-gray-300">unique secret</strong> per
              credential that never leaves the device.
            </li>
            <li>
              Given a <strong className="text-gray-300">salt</strong> (the
              Ticket ID), it outputs 32 deterministic bytes.
            </li>
            <li>
              <strong className="text-gray-300">Same credential + same Ticket ID = same key</strong>,
              every time, on any device with the same authenticator.
            </li>
          </ul>
        </section>

        {/* Step 1: Register */}
        <section className="bg-gray-900 rounded-lg p-6 space-y-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-indigo-600 text-xs font-bold shrink-0">
              1
            </span>
            <h2 className="text-lg font-semibold">Register a credential</h2>
          </div>
          <p className="text-gray-400 text-sm">
            Create a WebAuthn credential with PRF enabled on your authenticator.
            You only need to do this once.
          </p>
          <div className="flex gap-3">
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="flex-1 rounded-md bg-gray-800 border border-gray-700 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            <button
              onClick={handleRegister}
              disabled={status === "loading"}
              className="rounded-md bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 px-5 py-2 text-sm font-medium transition-colors cursor-pointer whitespace-nowrap"
            >
              Register
            </button>
          </div>
          {registered && (
            <p className="text-emerald-400 text-xs">
              Credential registered with PRF support.
            </p>
          )}
        </section>

        {/* Step 2: Derive */}
        <section className="bg-gray-900 rounded-lg p-6 space-y-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-600 text-xs font-bold shrink-0">
              2
            </span>
            <h2 className="text-lg font-semibold">Derive a private key</h2>
          </div>
          <p className="text-gray-400 text-sm">
            Enter a Ticket ID to use as salt. Sign in with your credential to
            evaluate PRF and derive the key. The same Ticket ID always produces
            the same key.
          </p>
          <div className="flex gap-3">
            <input
              type="text"
              placeholder="Ticket ID (e.g. invoice-42)"
              value={ticketId}
              onChange={(e) => setTicketId(e.target.value)}
              className="flex-1 rounded-md bg-gray-800 border border-gray-700 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500"
            />
            <button
              onClick={handleDerive}
              disabled={status === "loading"}
              className="rounded-md bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-5 py-2 text-sm font-medium transition-colors cursor-pointer whitespace-nowrap"
            >
              Derive Key
            </button>
          </div>
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

        {/* Derived key display */}
        {derivedKeyHex && (
          <section className="bg-gray-900 rounded-lg p-6 space-y-4 border border-emerald-800">
            <h2 className="text-lg font-semibold text-emerald-400">
              Derived Private Key
            </h2>
            <p className="text-gray-400 text-xs">
              Ticket ID: <code className="text-amber-300">{usedTicketId}</code>
            </p>

            <div>
              <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">
                Raw scalar (hex, 32 bytes)
              </h3>
              <pre className="bg-gray-800 rounded-md p-3 text-xs break-all whitespace-pre-wrap select-all">
                {derivedKeyHex}
              </pre>
            </div>

            <div>
              <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">
                PEM (PKCS#8)
              </h3>
              <pre className="bg-gray-800 rounded-md p-3 text-xs break-all whitespace-pre-wrap select-all">
                {derivedKeyPem}
              </pre>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

export default App;
