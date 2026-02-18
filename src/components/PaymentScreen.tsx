import { useState } from "react";
import { storePayment } from "../lib/fakeBackend";

interface PaymentScreenProps {
  ecdsaPublicKeyJwk: JsonWebKey;
  onPaymentComplete: () => void;
  onError: (error: string) => void;
}

export default function PaymentScreen({
  ecdsaPublicKeyJwk,
  onPaymentComplete,
  onError,
}: PaymentScreenProps) {
  const [processing, setProcessing] = useState(false);
  const [step, setStep] = useState<"form" | "processing" | "done">("form");

  const handlePay = async () => {
    setProcessing(true);
    setStep("processing");
    try {
      // Simulate payment processing delay
      await new Promise((r) => setTimeout(r, 1200));

      const paymentRef = `PAY-${crypto.randomUUID()}`;
      const paymentDate = new Date().toISOString();

      // Store in fake backend
      await storePayment({
        paymentRef,
        paymentDate,
        ecdsaPublicKey: ecdsaPublicKeyJwk,
      });

      setStep("done");

      // Brief pause to show success before navigating
      await new Promise((r) => setTimeout(r, 500));

      onPaymentComplete();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setProcessing(false);
    }
  };

  return (
    <section className="bg-gray-900 rounded-lg p-6 space-y-5 border border-gray-800">
      <h2 className="text-xl font-semibold">Buy Event Ticket</h2>

      <div className="bg-gray-800 rounded-lg p-5 border border-gray-700 space-y-4">
        <div className="flex justify-between items-center">
          <span className="text-gray-300 font-medium">Event Ticket</span>
          <span className="text-2xl font-bold text-emerald-400">5.00 EUR</span>
        </div>
        <hr className="border-gray-700" />

        {/* Fake credit card form */}
        <div className="space-y-3">
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wide">
              Card number
            </label>
            <input
              type="text"
              value="4242 4242 4242 4242"
              readOnly
              className="w-full rounded-md bg-gray-900 border border-gray-600 px-3 py-2 text-sm text-gray-300 mt-1"
            />
          </div>
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="text-xs text-gray-500 uppercase tracking-wide">
                Expiry
              </label>
              <input
                type="text"
                value="12/28"
                readOnly
                className="w-full rounded-md bg-gray-900 border border-gray-600 px-3 py-2 text-sm text-gray-300 mt-1"
              />
            </div>
            <div className="flex-1">
              <label className="text-xs text-gray-500 uppercase tracking-wide">
                CVC
              </label>
              <input
                type="text"
                value="123"
                readOnly
                className="w-full rounded-md bg-gray-900 border border-gray-600 px-3 py-2 text-sm text-gray-300 mt-1"
              />
            </div>
          </div>
        </div>
      </div>

      <button
        onClick={handlePay}
        disabled={processing}
        className="w-full rounded-md bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-5 py-3 text-sm font-semibold transition-colors cursor-pointer"
      >
        {step === "form" && "Pay 5.00 EUR"}
        {step === "processing" && "Processing payment..."}
        {step === "done" && "Payment accepted!"}
      </button>

      {step === "processing" && (
        <p className="text-center text-gray-500 text-xs animate-pulse">
          Contacting payment provider...
        </p>
      )}
      {step === "done" && (
        <p className="text-center text-emerald-400 text-xs">
          Payment successful. Generating your ticket...
        </p>
      )}
    </section>
  );
}
