import { useState } from "react";
import {
  canonicalJsonStringify,
  verifySignature,
  jwkThumbprint,
} from "../lib/crypto";
import { lookupByPublicKey } from "../lib/fakeBackend";

interface VerificationResult {
  valid: boolean;
  signatureDate: string;
  paymentRef: string;
  paymentDate: string;
  publicKeyThumbprint: string;
  timeDelta: number;
  backendMatch: boolean;
  details: string;
}

export default function VerifierScreen() {
  const [jsonInput, setJsonInput] = useState("");
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [error, setError] = useState("");
  const [verifying, setVerifying] = useState(false);

  const handleVerify = async () => {
    setError("");
    setResult(null);
    setVerifying(true);

    try {
      const parsed = JSON.parse(jsonInput);
      const {
        ecdsaPublicKey,
        paymentRef,
        paymentDate,
        signatureDate,
        signature,
      } = parsed;

      if (!ecdsaPublicKey || !paymentRef || !paymentDate || !signatureDate || !signature) {
        throw new Error(
          "Missing required fields: ecdsaPublicKey, paymentRef, paymentDate, signatureDate, signature",
        );
      }

      // Re-import the public key
      const publicKey = await crypto.subtle.importKey(
        "jwk",
        ecdsaPublicKey,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"],
      );

      // Rebuild the canonical payload (without signature)
      const payloadObj = {
        ecdsaPublicKey,
        paymentDate,
        paymentRef,
        signatureDate,
      };
      const payloadString = canonicalJsonStringify(payloadObj);

      // Verify signature
      const valid = await verifySignature(publicKey, payloadString, signature);

      // Check time delta
      const sigTime = new Date(signatureDate).getTime();
      const now = Date.now();
      const timeDelta = Math.abs(now - sigTime) / 1000;

      // Look up in fake backend
      const backendRecord = await lookupByPublicKey(ecdsaPublicKey);

      // Compute thumbprint for display
      const thumbprint = await jwkThumbprint(ecdsaPublicKey);

      setResult({
        valid,
        signatureDate,
        paymentRef,
        paymentDate,
        publicKeyThumbprint: thumbprint,
        timeDelta,
        backendMatch:
          backendRecord !== null &&
          backendRecord.paymentRef === paymentRef &&
          backendRecord.paymentDate === paymentDate,
        details: valid
          ? `Signature is cryptographically valid. Time delta: ${timeDelta.toFixed(1)}s.`
          : "Signature verification FAILED. The data may have been tampered with.",
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setVerifying(false);
    }
  };

  const handlePasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setJsonInput(text);
    } catch {
      setError("Could not read clipboard. Please paste manually.");
    }
  };

  return (
    <section className="bg-gray-900 rounded-lg p-6 space-y-5 border border-gray-800">
      <h2 className="text-xl font-semibold">Verify Ticket</h2>
      <p className="text-gray-400 text-sm">
        Paste the JSON payload from an Aztec code to verify its ECDSA signature
        and check the payment record in the backend.
      </p>

      <div className="space-y-3">
        <div className="flex gap-2">
          <button
            onClick={handlePasteFromClipboard}
            className="rounded-md bg-gray-700 hover:bg-gray-600 px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer"
          >
            Paste from clipboard
          </button>
        </div>
        <textarea
          value={jsonInput}
          onChange={(e) => setJsonInput(e.target.value)}
          placeholder='{"ecdsaPublicKey":{...},"paymentRef":"PAY-...","paymentDate":"...","signatureDate":"...","signature":"..."}'
          rows={8}
          className="w-full rounded-md bg-gray-800 border border-gray-700 px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-y"
        />
        <button
          onClick={handleVerify}
          disabled={verifying || !jsonInput.trim()}
          className="w-full rounded-md bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 px-5 py-2.5 text-sm font-medium transition-colors cursor-pointer"
        >
          {verifying ? "Verifying..." : "Verify Signature"}
        </button>
      </div>

      {error && (
        <div className="bg-red-900/50 text-red-300 border border-red-800 rounded-md p-3 text-sm">
          {error}
        </div>
      )}

      {result && (
        <div
          className={`rounded-lg p-5 space-y-4 border ${
            result.valid
              ? "bg-emerald-900/30 border-emerald-700"
              : "bg-red-900/30 border-red-700"
          }`}
        >
          <div className="flex items-center gap-3">
            <span
              className={`text-2xl ${result.valid ? "text-emerald-400" : "text-red-400"}`}
            >
              {result.valid ? "VALID" : "INVALID"}
            </span>
          </div>

          <p
            className={`text-sm ${result.valid ? "text-emerald-300" : "text-red-300"}`}
          >
            {result.details}
          </p>

          <div className="grid grid-cols-2 gap-3 text-sm">
            <CheckItem
              label="Signature"
              ok={result.valid}
              detail={result.valid ? "Cryptographically valid" : "FAILED"}
            />
            <CheckItem
              label="Time delta"
              ok={result.timeDelta < 10}
              detail={`${result.timeDelta.toFixed(1)}s ${result.timeDelta < 10 ? "(fresh)" : "(stale!)"}`}
            />
            <CheckItem
              label="Backend record"
              ok={result.backendMatch}
              detail={
                result.backendMatch
                  ? "Payment ref + date match"
                  : "No matching record"
              }
            />
            <CheckItem
              label="Public key"
              ok={true}
              detail={result.publicKeyThumbprint.slice(0, 16) + "..."}
            />
          </div>

          <div>
            <span className="text-xs text-gray-500 uppercase tracking-wide">
              Payment Ref
            </span>
            <p className="text-gray-300 font-mono text-xs mt-1">
              {result.paymentRef}
            </p>
          </div>
          <div>
            <span className="text-xs text-gray-500 uppercase tracking-wide">
              Signature Date
            </span>
            <p className="text-gray-300 font-mono text-xs mt-1">
              {result.signatureDate}
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

function CheckItem({
  label,
  ok,
  detail,
}: {
  label: string;
  ok: boolean;
  detail: string;
}) {
  return (
    <div className="flex items-start gap-2">
      <span className={`mt-0.5 ${ok ? "text-emerald-400" : "text-red-400"}`}>
        {ok ? "[OK]" : "[!!]"}
      </span>
      <div>
        <p className="text-gray-300 text-xs font-medium">{label}</p>
        <p className="text-gray-500 text-xs">{detail}</p>
      </div>
    </div>
  );
}
