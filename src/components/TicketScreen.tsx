import { useEffect, useRef, useState } from "react";
import type { PaymentRecord } from "../lib/fakeBackend";
import {
  canonicalJsonStringify,
  signPayload,
} from "../lib/crypto";
import { renderAztecCode } from "../lib/aztec";

interface TicketScreenProps {
  record: PaymentRecord;
  ecdsaPrivateKey: CryptoKey;
  ecdsaPublicKeyJwk: JsonWebKey;
}

interface SignedPayload {
  ecdsaPublicKey: JsonWebKey;
  paymentDate: string;
  paymentRef: string;
  signatureDate: string;
  signature: string;
}

export default function TicketScreen({
  record,
  ecdsaPrivateKey,
  ecdsaPublicKeyJwk,
}: TicketScreenProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [signedPayload, setSignedPayload] = useState<SignedPayload | null>(
    null,
  );
  const [sigCount, setSigCount] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    const signAndRender = async () => {
      try {
        const signatureDate = new Date().toISOString();

        // Build the payload to sign (canonical JSON, without signature field)
        const payloadObj = {
          ecdsaPublicKey: ecdsaPublicKeyJwk,
          paymentDate: record.paymentDate,
          paymentRef: record.paymentRef,
          signatureDate,
        };
        const payloadString = canonicalJsonStringify(payloadObj);

        // Sign
        const signature = await signPayload(ecdsaPrivateKey, payloadString);

        if (cancelled) return;

        const fullPayload: SignedPayload = {
          ...payloadObj,
          signature,
        };

        setSignedPayload(fullPayload);
        setSigCount((c) => c + 1);

        // Render Aztec code
        const fullPayloadString = canonicalJsonStringify(fullPayload);
        if (canvasRef.current) {
          await renderAztecCode(canvasRef.current, fullPayloadString, 3);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
        }
      }
    };

    // Sign immediately, then every 4 seconds
    signAndRender();
    const interval = setInterval(signAndRender, 4000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [ecdsaPrivateKey, ecdsaPublicKeyJwk, record]);

  // Compute raw public key bytes for display
  const pubKeyDisplay = ecdsaPublicKeyJwk.x && ecdsaPublicKeyJwk.y
    ? `x: ${ecdsaPublicKeyJwk.x}\ny: ${ecdsaPublicKeyJwk.y}`
    : JSON.stringify(ecdsaPublicKeyJwk, null, 2);

  return (
    <section className="bg-gray-900 rounded-lg p-6 space-y-5 border border-emerald-800">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-emerald-400">
          Your Ticket
        </h2>
        <span className="text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded">
          Signature #{sigCount}
        </span>
      </div>

      {error && (
        <div className="bg-red-900/50 text-red-300 border border-red-800 rounded-md p-3 text-sm">
          {error}
        </div>
      )}

      {/* Aztec code */}
      <div className="flex justify-center bg-white rounded-lg p-4">
        <canvas ref={canvasRef} />
      </div>

      <p className="text-center text-gray-500 text-xs">
        Aztec code refreshes every 4 seconds with a new signature
      </p>

      {/* Ticket info */}
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div>
            <span className="text-xs text-gray-500 uppercase tracking-wide">
              Payment Ref
            </span>
            <p className="text-gray-200 font-mono text-xs mt-1 break-all">
              {record.paymentRef}
            </p>
          </div>
          <div>
            <span className="text-xs text-gray-500 uppercase tracking-wide">
              Payment Date
            </span>
            <p className="text-gray-200 font-mono text-xs mt-1">
              {record.paymentDate}
            </p>
          </div>
        </div>

        <DebugSection title="ECDSA Public Key (JWK)">
          <pre className="text-xs break-all whitespace-pre-wrap">
            {pubKeyDisplay}
          </pre>
        </DebugSection>

        <DebugSection title="JWK Thumbprint (storage key)">
          <pre className="text-xs break-all">{record.thumbprint}</pre>
        </DebugSection>

        {signedPayload && (
          <>
            <DebugSection title="Signed Payload (canonical JSON)">
              <pre className="text-xs break-all whitespace-pre-wrap">
                {canonicalJsonStringify({
                  ecdsaPublicKey: signedPayload.ecdsaPublicKey,
                  paymentDate: signedPayload.paymentDate,
                  paymentRef: signedPayload.paymentRef,
                  signatureDate: signedPayload.signatureDate,
                })}
              </pre>
            </DebugSection>

            <DebugSection title="ECDSA Signature (ASN.1 DER, base64url)">
              <pre className="text-xs break-all">{signedPayload.signature}</pre>
            </DebugSection>

            <DebugSection title="Full Aztec Payload">
              <pre className="text-xs break-all whitespace-pre-wrap">
                {canonicalJsonStringify(signedPayload)}
              </pre>
            </DebugSection>

            <DebugSection title="Signature Date">
              <pre className="text-xs">{signedPayload.signatureDate}</pre>
            </DebugSection>
          </>
        )}
      </div>
    </section>
  );
}

function DebugSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <span className="text-xs text-gray-500 uppercase tracking-wide">
        {title}
      </span>
      <div className="bg-gray-800 rounded-md p-3 mt-1 text-gray-300 select-all">
        {children}
      </div>
    </div>
  );
}

