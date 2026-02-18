import express from "express";
import { issueDosipas, type IssueRequest } from "./dosipas.js";
import { getLevel1PublicKey } from "./kms.js";

const app = express();
app.use(express.json());

/**
 * POST /v1/issue
 *
 * Accepts a level 2 public key (and rail ticket data), creates a
 * DOSIPAS level 1 structure integrating the level 2 public key,
 * and signs level 1 with the GCP KMS HSM key.
 *
 * Request body: IssueRequest (JSON)
 * Response: { barcode: string } (hex-encoded DOSIPAS barcode)
 */
app.post("/v1/issue", async (req, res) => {
  try {
    const body = req.body as IssueRequest;

    if (!body.level2PublicKey) {
      res.status(400).json({ error: "level2PublicKey is required" });
      return;
    }
    if (!body.railTicket) {
      res.status(400).json({ error: "railTicket is required" });
      return;
    }

    const result = await issueDosipas(body);
    res.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Internal error";
    console.error("POST /v1/issue error:", err);
    res.status(500).json({ error: message });
  }
});

/**
 * GET /v1/keys
 *
 * Returns the level 1 public key (from GCP KMS HSM) as a JSON array.
 * The key is in SPKI DER format, base64-encoded.
 */
app.get("/v1/keys", async (_req, res) => {
  try {
    const publicKeyDer = await getLevel1PublicKey();
    const publicKeyBase64 = Buffer.from(publicKeyDer).toString("base64");
    res.json([{ publicKey: publicKeyBase64, algorithm: "EC_P256" }]);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Internal error";
    console.error("GET /v1/keys error:", err);
    res.status(500).json({ error: message });
  }
});

const port = parseInt(process.env.PORT ?? "8080", 10);
app.listen(port, () => {
  console.log(`dosipas-issuer listening on port ${port}`);
});
