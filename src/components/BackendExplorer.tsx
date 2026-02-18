import { useState } from "react";
import {
  listAllRecords,
  deleteRecord,
  clearAllRecords,
} from "../lib/fakeBackend";
import type { PaymentRecord } from "../lib/fakeBackend";

export default function BackendExplorer() {
  const [records, setRecords] = useState<PaymentRecord[]>(() =>
    listAllRecords(),
  );

  const refresh = () => {
    setRecords(listAllRecords());
  };

  const handleDelete = (thumbprint: string) => {
    deleteRecord(thumbprint);
    refresh();
  };

  const handleClearAll = () => {
    clearAllRecords();
    refresh();
  };

  return (
    <section className="bg-gray-900 rounded-lg p-6 space-y-5 border border-gray-800">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Backend Explorer</h2>
        <div className="flex gap-2">
          <button
            onClick={refresh}
            className="rounded-md bg-gray-700 hover:bg-gray-600 px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer"
          >
            Refresh
          </button>
          {records.length > 0 && (
            <button
              onClick={handleClearAll}
              className="rounded-md bg-red-900 hover:bg-red-800 px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer text-red-300"
            >
              Clear all
            </button>
          )}
        </div>
      </div>

      <p className="text-gray-400 text-sm">
        All payment records stored in the fake backend (localStorage). Keyed by
        ECDSA public key JWK thumbprint.
      </p>

      {records.length === 0 ? (
        <div className="bg-gray-800 rounded-md p-6 text-center text-gray-500 text-sm">
          No records in the backend.
        </div>
      ) : (
        <div className="space-y-4">
          {records.map((record) => (
            <div
              key={record.thumbprint}
              className="bg-gray-800 rounded-lg p-4 border border-gray-700 space-y-3"
            >
              <div className="flex items-start justify-between">
                <span className="text-xs text-gray-500 font-mono">
                  {record.thumbprint}
                </span>
                <button
                  onClick={() => handleDelete(record.thumbprint)}
                  className="text-xs text-red-400 hover:text-red-300 cursor-pointer"
                >
                  Delete
                </button>
              </div>

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

              <div>
                <span className="text-xs text-gray-500 uppercase tracking-wide">
                  ECDSA Public Key (JWK)
                </span>
                <pre className="bg-gray-900 rounded-md p-2 mt-1 text-xs text-gray-300 break-all whitespace-pre-wrap select-all">
                  {JSON.stringify(record.ecdsaPublicKey, null, 2)}
                </pre>
              </div>

              <div>
                <span className="text-xs text-gray-500 uppercase tracking-wide">
                  Raw localStorage value
                </span>
                <pre className="bg-gray-900 rounded-md p-2 mt-1 text-xs text-gray-400 break-all whitespace-pre-wrap">
                  {JSON.stringify(record, null, 2)}
                </pre>
              </div>
            </div>
          ))}
        </div>
      )}

      <p className="text-gray-600 text-xs">
        {records.length} record{records.length !== 1 ? "s" : ""} in localStorage
        (prefix: dosipas:)
      </p>
    </section>
  );
}
