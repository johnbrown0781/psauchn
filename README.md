## Open Science Artifacts

This repository contains the anonymized reference implementation that accompanies the paper.  
It is intended to help reviewers reproduce the paper's core mechanisms and to serve as a compact, readable starting point for further experimentation.

The artifacts include:

- **Cloudflare Workers edge function** that performs **stateless verification** of the authentication header (early rejection at the edge).
- **Reference provisioning logic** that issues compact JWT credentials and derives per-client secrets.
- **Reference client** that constructs the authentication header and sends test requests.
- **Helper utilities** included inline for easier review (each file is self-contained and includes the helper functions it needs).

> **Scope note:** This repository is intentionally minimal and anonymized. It demonstrates the protocol mechanics and verification pipeline without production dependencies, monitoring, or deployment-specific hardening.

---

## Repository Layout

- `edgefunction.js`  
  Cloudflare Worker that:
  - reads authentication from HTTP header (`unattended-client-auth`) or URL parameter (`uca`),
  - reconstructs candidate timestamps from `TimeByte`,
  - recomputes and validates `AuthHash`,
  - verifies the JWT signature (provisioning credential),
  - verifies the client's Ed25519 request signature,
  - rejects unauthenticated/abusive traffic before origin fetch.

- `client.js`  
  Reference client implementation that:
  - constructs `AuthHash`, `TimeByte`, and Ed25519 `Signature`,
  - builds the authentication header,
  - sends test HTTPS requests.

- `provisioning.js`  
  Reference provisioning implementation that:
  - issues signed JWT credentials (EdDSA/Ed25519),
  - derives per-client `ClientAuthSecret` using `HMAC-SHA256(BackendDerivationKey, ClientID)`,

---

## Quick Review Guide (What to Look For)

The key parts are:

1. **Auth header parsing and early rejection** (`edgefunction.js`, `verifyAuthenticationHeader`)
2. **Timestamp compression and replay window reconstruction** (`TimeByte` + candidate timestamp enumeration)
3. **AuthHash recomputation logic** (`computeAuthHash`)
4. **JWT verification and KeyID-based signing key selection** (`verifyJwtSignature`, `signingKeyMap`)
5. **Client signature verification (Ed25519)** (`verifyEd25519`, and 'highly constrained' bypass logic)
6. **Provisioning outputs** (`provisioning.js`: JWT issuance + masked `ClientAuthSecret`)

---

## Notes on Self-Containment

For easier analysis and review, each file embeds the helper functions it requires (base64url conversion, hashing helpers, XOR masking helpers, etc.) instead of importing a shared utility module. This is deliberate: reviewers can read each artifact independently without jumping across files.

---

## Note (Paper Erratum)

In the submitted paper, the `AuthHash` definition **accidentally omits** the `|| "\n"` delimiter after concatenated fields (a typesetting/omission issue).
The **reference implementation in this repository is correct** and computes `AuthHash` using newline-delimited concatenation exactly as intended.

