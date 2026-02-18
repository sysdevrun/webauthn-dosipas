import { useState } from "react";
import AuthScreen from "./components/AuthScreen";
import PaymentScreen from "./components/PaymentScreen";
import TicketScreen from "./components/TicketScreen";
import VerifierScreen from "./components/VerifierScreen";
import BackendExplorer from "./components/BackendExplorer";
import { deriveKeys, bytesToHex } from "./lib/crypto";
import { lookupByPublicKey } from "./lib/fakeBackend";
import type { PaymentRecord } from "./lib/fakeBackend";
import type { DerivedKeys } from "./lib/crypto";

// ---------------------------------------------------------------------------
// Application state machine
// ---------------------------------------------------------------------------

type AppState = "auth" | "payment" | "ticket" | "error";
type Tab = "app" | "verifier" | "backend";

function App() {
  // State machine
  const [appState, setAppState] = useState<AppState>("auth");
  const [activeTab, setActiveTab] = useState<Tab>("app");
  const [error, setError] = useState("");

  // Crypto state (displayed in debug panel)
  const [prfOutputHex, setPrfOutputHex] = useState("");
  const [derivedKeysState, setDerivedKeysState] = useState<DerivedKeys | null>(
    null,
  );
  const [paymentRecord, setPaymentRecord] = useState<PaymentRecord | null>(
    null,
  );

  // Debug panel toggle
  const [showDebug, setShowDebug] = useState(true);

  // -------------------------------------------------------------------------
  // Auth → derive keys → check backend → payment or ticket
  // -------------------------------------------------------------------------
  const handleAuthenticated = async (params: {
    email: string;
    prfOutput: Uint8Array;
    credentialId: Uint8Array;
    mode: "register" | "signin";
  }) => {
    try {
      setError("");
      setPrfOutputHex(bytesToHex(params.prfOutput));

      // Derive keys from PRF output
      const keys = await deriveKeys(params.prfOutput);
      setDerivedKeysState(keys);

      // Check fake backend for existing payment
      const record = await lookupByPublicKey(keys.ecdsaKeyPair.publicKeyJwk);

      if (record) {
        // Existing payment found → go to ticket
        setPaymentRecord(record);
        setAppState("ticket");
      } else {
        // No payment → go to payment screen
        setAppState("payment");
      }
    } catch (err) {
      handleError(err instanceof Error ? err.message : String(err));
    }
  };

  // -------------------------------------------------------------------------
  // Payment complete → store record → ticket
  // -------------------------------------------------------------------------
  const handlePaymentComplete = async () => {
    if (!derivedKeysState) return;
    try {
      // Look up the freshly stored record
      const record = await lookupByPublicKey(
        derivedKeysState.ecdsaKeyPair.publicKeyJwk,
      );
      if (!record) throw new Error("Payment record not found after storage.");
      setPaymentRecord(record);
      setAppState("ticket");
    } catch (err) {
      handleError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleError = (msg: string) => {
    setError(msg);
    setAppState("error");
  };

  const handleReset = () => {
    setAppState("auth");
    setError("");
    setPrfOutputHex("");
    setDerivedKeysState(null);
    setPaymentRecord(null);
  };

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-4">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <header className="text-center space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">
            DOSIPAS Ticket Demo
          </h1>
          <p className="text-gray-400 text-sm max-w-lg mx-auto">
            WebAuthn PRF + HKDF + ECDSA P-256 deterministic ticket signing
          </p>
        </header>

        {/* Tabs */}
        <nav className="flex gap-1 bg-gray-900 rounded-lg p-1">
          {(
            [
              ["app", "Ticket App"],
              ["verifier", "Verifier"],
              ["backend", "Backend Explorer"],
            ] as const
          ).map(([tab, label]) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 rounded-md px-3 py-2 text-sm font-medium transition-colors cursor-pointer ${
                activeTab === tab
                  ? "bg-gray-700 text-white"
                  : "text-gray-400 hover:text-gray-200"
              }`}
            >
              {label}
            </button>
          ))}
        </nav>

        {/* Tab content */}
        {activeTab === "app" && (
          <div className="space-y-6">
            {/* State indicator */}
            <div className="flex items-center gap-3">
              <StateBadge state={appState} />
              {appState !== "auth" && (
                <button
                  onClick={handleReset}
                  className="text-xs text-gray-500 hover:text-gray-300 cursor-pointer"
                >
                  Reset
                </button>
              )}
            </div>

            {/* Main content based on state */}
            {appState === "auth" && (
              <AuthScreen
                onAuthenticated={handleAuthenticated}
                onError={(msg) => handleError(msg)}
              />
            )}

            {appState === "payment" && derivedKeysState && (
              <PaymentScreen
                ecdsaPublicKeyJwk={derivedKeysState.ecdsaKeyPair.publicKeyJwk}
                onPaymentComplete={handlePaymentComplete}
                onError={(msg) => handleError(msg)}
              />
            )}

            {appState === "ticket" &&
              derivedKeysState &&
              paymentRecord && (
                <TicketScreen
                  record={paymentRecord}
                  ecdsaPrivateKey={derivedKeysState.ecdsaKeyPair.privateKey}
                  ecdsaPublicKeyJwk={
                    derivedKeysState.ecdsaKeyPair.publicKeyJwk
                  }
                />
              )}

            {appState === "error" && (
              <div className="bg-red-900/50 text-red-300 border border-red-800 rounded-lg p-5 space-y-3">
                <h2 className="font-semibold">Error</h2>
                <p className="text-sm">{error}</p>
                <button
                  onClick={handleReset}
                  className="rounded-md bg-red-800 hover:bg-red-700 px-4 py-2 text-sm font-medium transition-colors cursor-pointer"
                >
                  Start over
                </button>
              </div>
            )}

            {/* Debug panel — shows all internal state */}
            <DebugPanel
              show={showDebug}
              onToggle={() => setShowDebug(!showDebug)}
              appState={appState}
              prfOutputHex={prfOutputHex}
              derivedKeys={derivedKeysState}
              paymentRecord={paymentRecord}
            />
          </div>
        )}

        {activeTab === "verifier" && <VerifierScreen />}
        {activeTab === "backend" && <BackendExplorer />}

        {/* Footer */}
        <footer className="text-center text-gray-600 text-xs py-4">
          This is a demo application. The "backend" is localStorage. No data
          leaves your browser.
        </footer>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Debug panel — shows every internal state of the app
// ---------------------------------------------------------------------------

function DebugPanel({
  show,
  onToggle,
  appState,
  prfOutputHex,
  derivedKeys,
  paymentRecord,
}: {
  show: boolean;
  onToggle: () => void;
  appState: AppState;
  prfOutputHex: string;
  derivedKeys: DerivedKeys | null;
  paymentRecord: PaymentRecord | null;
}) {
  return (
    <section className="border border-gray-800 rounded-lg overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between bg-gray-900 px-4 py-3 text-sm font-medium text-gray-400 hover:text-gray-200 transition-colors cursor-pointer"
      >
        <span>Internal State (Debug)</span>
        <span>{show ? "Hide" : "Show"}</span>
      </button>

      {show && (
        <div className="bg-gray-900/50 p-4 space-y-4 text-xs">
          <DebugRow label="App state" value={appState} />

          {prfOutputHex && (
            <DebugRow label="PRF output (32 bytes, hex)" value={prfOutputHex} />
          )}

          {derivedKeys && (
            <>
              <DebugRow
                label="ECDSA scalar (hex)"
                value={derivedKeys.ecdsaScalarHex}
              />
              <DebugRow
                label="ECDSA public key (JWK)"
                value={JSON.stringify(
                  derivedKeys.ecdsaKeyPair.publicKeyJwk,
                  null,
                  2,
                )}
                pre
              />
              <DebugRow
                label="AES-GCM-256 key"
                value="[CryptoKey — non-extractable, encrypt+decrypt]"
              />
              <DebugRow
                label="ECDSA private key"
                value="[CryptoKey — extractable, sign]"
              />
            </>
          )}

          {paymentRecord && (
            <DebugRow
              label="Payment record (from backend)"
              value={JSON.stringify(paymentRecord, null, 2)}
              pre
            />
          )}

          {!prfOutputHex && (
            <p className="text-gray-600 italic">
              Authenticate to populate internal state.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function DebugRow({
  label,
  value,
  pre,
}: {
  label: string;
  value: string;
  pre?: boolean;
}) {
  return (
    <div>
      <span className="text-gray-500 uppercase tracking-wide">{label}</span>
      {pre ? (
        <pre className="bg-gray-800 rounded-md p-2 mt-1 text-gray-300 break-all whitespace-pre-wrap select-all">
          {value}
        </pre>
      ) : (
        <p className="bg-gray-800 rounded-md p-2 mt-1 text-gray-300 font-mono break-all select-all">
          {value}
        </p>
      )}
    </div>
  );
}

function StateBadge({ state }: { state: AppState }) {
  const colors: Record<AppState, string> = {
    auth: "bg-indigo-900/60 text-indigo-300 border-indigo-700",
    payment: "bg-amber-900/60 text-amber-300 border-amber-700",
    ticket: "bg-emerald-900/60 text-emerald-300 border-emerald-700",
    error: "bg-red-900/60 text-red-300 border-red-700",
  };
  const labels: Record<AppState, string> = {
    auth: "Authentication",
    payment: "Payment",
    ticket: "Ticket Active",
    error: "Error",
  };
  return (
    <span
      className={`text-xs font-medium px-3 py-1 rounded-full border ${colors[state]}`}
    >
      {labels[state]}
    </span>
  );
}

export default App;
