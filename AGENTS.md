# AGENTS.md

Repository guide for coding agents. For using Xipher (the CLI, library, or web app), read
https://xipher.org/AGENTS.md instead — this file is about changing the code.

## Layout

- `xipher_*.go` — the library (`package xipher`). `xipher_doc.go` is the godoc source of truth.
- `internal/crypto/{asx,ecc,hyb,kyb,xcp}` — key exchange, hybrid PQ, ML-KEM, and the chunked AEAD.
- `internal/cli/` — Cobra CLI. Commands in `internal/cli/commands/`, flags declared in `const.go`.
- `internal/kms/` — XKMS server (`server.go` route table, `config.go` schema, `credential.go` derivation).
- `internal/wasm/`, `internal/sharedlib/` — WASM and C shared-library entry points.
- `web/` — the static site (served by Cloudflare Pages). `web/docs/index.html` is the documentation page,
  `web/docs.md` is its Markdown twin.
- `action/` — GitHub Action wrapper (Node).

## Commands

```bash
go test -v $(go list ./... | grep -v internal/wasm)   # unit tests (matches CI)
go build ./...
go vet ./...
```

## Invariants — do not break these

1. **Wire-format compatibility.** New releases must decrypt older ciphertext (see the version notes in
   `README.md` and `xipher_doc.go`). Single-chunk ciphertext (under 64 KiB) has a frozen on-the-wire
   representation.
2. **Godoc is API truth.** Any exported change in `xipher_*.go` needs `xipher_doc.go` updated in the same
   commit; `pkg.go.dev` is linked from the docs and from `llms.txt`.
3. **`web/docs/index.html` is docs truth.** `web/docs.md` is a checked-in Markdown copy; when you change the
   HTML, update `docs.md` in the same change and keep the `<a id="…">` anchors matching the section ids.
4. **No secrets in the site.** `web/` is public and `web/.well-known/xipher` contains only a public key.
5. **CSP stays strict.** `web/index.html` and `web/docs/index.html` use `default-src 'none'`. Inline scripts
   need a CSP hash; prefer external files.
6. **XKMS config changes** must update all four places: `internal/kms/config.go`, `internal/kms/xkms.example.yaml`,
   the XKMS configuration section in `web/docs/index.html`, and (if routes change) `web/xkms/openapi.json`.

## Site files that agents consume

These are part of the product surface; keep them accurate:

- `web/llms.txt`, `web/docs/llms.txt` — curated indexes; every link must point at `web/docs.md` anchors.
- `web/AGENTS.md` — operator guide served at `/AGENTS.md`.
- `web/docs.md` — canonical documentation URL (Markdown twin of `web/docs/index.html`).
- `web/_redirects`, `web/_headers` — aliases and content types for `.well-known`, Markdown, and indexes.
- `web/robots.txt` — allow-all plus `Content-Signal`.
- `web/xkms/openapi.json` — must list exactly the routes registered in `internal/kms/server.go`.
- `web/skills/xipher/SKILL.md` — installable agent skill.

## Release

Tagging `vX.Y.Z` runs `.github/workflows/release.yaml`. It copies `web/` to `.ignore/web/` and stamps the
version into the HTML; goreleaser packages it as `xipher-web.zip`. `.github/workflows/pages.yaml` deploys
that zip to Cloudflare Pages. A change under `web/` is not live until a release is tagged and Pages redeploys.

Do not commit generated build output (`dist/`, `.ignore/`).
