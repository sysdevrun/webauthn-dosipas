# webauthn-dosipas

Derive deterministic ECDSA P-256 private keys from a WebAuthn credential using the [PRF extension](https://w3c.github.io/webauthn/#prf-extension). A Ticket ID is used as salt so that the same credential + same Ticket ID always produces the same private key.

**Live demo:** <https://sysdevrun.github.io/webauthn-dosipas/>

## How it works

1. **Register** — Create a WebAuthn credential with `prf: {}` enabled. The authenticator generates a unique per-credential secret that never leaves the device.
2. **Derive** — Authenticate with the credential while passing a Ticket ID as salt. The authenticator evaluates `PRF(secret, SHA-256(ticketId))` and returns 32 deterministic bytes. Those bytes are used as the raw scalar of an ECDSA P-256 private key, displayed in hex and PEM (PKCS#8) formats.

The key is never stored anywhere — it is re-derived on the fly every time you authenticate with the same Ticket ID.

## Requirements

- A WebAuthn-compatible authenticator that supports the **PRF** extension (Chrome 116+, Edge 116+, macOS/iCloud Keychain on Safari 18+, etc.).
- The page must be served over **HTTPS** (GitHub Pages provides this).

## Development

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

## Author

**Théophile Helleboid**

## License

[MIT](LICENSE)
