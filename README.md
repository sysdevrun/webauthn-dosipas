# webauthn-dosipas

A demo application that generates an ECDSA P-256 private key, stores it inside a WebAuthn authenticator using the [largeBlob extension](https://w3c.github.io/webauthn/#sctn-large-blob-extension), and lets the user recover the key by signing in later.

**Live demo:** <https://sysdevrun.github.io/webauthn-dosipas/>

## How it works

1. **Register** — An ECDSA P-256 private key is generated in the browser using the Web Crypto API. A WebAuthn credential is created with `largeBlob: { support: "required" }`, then the private key bytes are written to the authenticator's largeBlob storage.
2. **Recover** — The user authenticates with their existing WebAuthn credential. The largeBlob is read back, and the private key is displayed in hex and PEM formats.

## Requirements

- A WebAuthn-compatible authenticator that supports the **largeBlob** extension (e.g. YubiKey 5, recent Android/Chrome, etc.).
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
