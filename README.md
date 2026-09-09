# Ordivon Artifact Release Trust

Minimal private carrier for the Artifact Build & Delivery production Sigstore keyless identity.

The production workflow separates prepare/sign/publish privileges. Only the sign job receives `id-token: write`; it executes no third-party `uses:` steps. Stable signer identity lives in the trust policy while the exact workflow commit SHA is authorized through the GitHub environment.
