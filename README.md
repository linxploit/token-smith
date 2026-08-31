<div align="center">

```
╭──────────────────────────────────────╮
│                                      │
│  ◆  T  O  K  E  N  S  M  I  T  H  ◆ │
│                                      │
│       Forge · Crack · Fortify        │
│                                      │
╰──────────────────────────────────────╯
```

### ✦ JWT Security Analyzer & Weak-Secret Auditor ✦

**Offline by default. No network request without `--live-test`.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Made by Mindless](https://img.shields.io/badge/Made%20by-Mindless-ff69b4.svg)](https://linxploit.com/founder)
[![Linxploit](https://img.shields.io/badge/Linxploit-linxploit.com-black.svg)](https://linxploit.com)

**Made by [Mindless](https://linxploit.com/founder) — Founder & CEO of [Linxploit](https://linxploit.com)**

</div>

---

## 🧠 What is TokenSmith?

**TokenSmith** takes a JSON Web Token you already have — from your own application, or one captured during an authorized engagement — and puts it through the standard battery of checks that separate a real JWT security review from a quick glance at jwt.io: claim hygiene, header risk signals, an offline weak-secret audit, and forgery generation for the two classic JWT authentication-bypass techniques.

Everything runs **locally and offline by default**. Nothing is sent anywhere unless you explicitly opt into `--live-test` — and even then, TokenSmith only replays a token it already forged, against an endpoint you specify, to see how the server responds.

---

## ✨ Features

- 🎨 **A completely different visual identity** — a compact engraved seal/badge instead of a full-width block-letter banner, with its own warm forge-gold gradient.
- 🔓 **Full decode & structural analysis** — header and payload pretty-printed, signature length shown, malformed tokens caught cleanly.
- 🗝️ **Offline weak-secret audit** for HS256/HS384/HS512 — checks the token's signature against 50 built-in common/default JWT secrets (or your own `--wordlist`), entirely as local HMAC computation. No network call, no different in principle from any password-strength checker.
- ⚒️ **`alg:none` forgery generation** — produces all four common case variants (`none`, `None`, `NONE`, `nOnE`) some libraries only check case-sensitively for, ready for you to test against your own verifier.
- 🔁 **RS256→HS256 algorithm-confusion forgery** — given the server's RSA/EC public key (`--public-key`), forges an HS256 token signed using the public key bytes as the HMAC secret — the exact technique that fools a verifier which blindly trusts the `alg` header and reuses the same key material for both algorithms. **Cryptographically verified correct** in this project's own test suite.
- ✅ **Public-key signature verification** — confirms whether a token's RS256/RS384/RS512/PS256 signature is genuinely valid against a given public key.
- 🕵️ **Header risk signals** — flags `jku`/`x5u` (external key URLs — a verifier that fetches these without an allowlist can be handed an attacker-controlled signing key) and suspicious `kid` values (path traversal, SQL/shell injection patterns).
- 📋 **Claim hygiene checks** — missing/absent expiration, unusually long token lifetime, missing `iss`/`aud`, and claim names that suggest sensitive data landed in a payload that's base64-encoded, **not encrypted**.
- 🌐 **Optional live testing** (`--live-test` + `--verify-url`) — replay any forged token against a real endpoint and see the HTTP response, gated behind an explicit authorization confirmation.
- 📊 **Exportable reports** — full **JSON** (every field, every forged token, every finding) or a flat **CSV** of findings.

---

## 📸 Preview

```
╭──────────────────────────────────────╮
│  ◆  T  O  K  E  N  S  M  I  T  H  ◆  │
╰──────────────────────────────────────╯

◆ WEAK-SECRET AUDIT
───────────────────
  ⚠ SECRET RECOVERED: 'secret'
  This token can be forged by anyone who knows this secret.
  1 candidate(s) checked in 0.000s

◆ FORGED TOKENS (for authorized manual/live testing)
────────────────────────────────────────────────────
  'alg:none' variants — test whether your verifier rejects ALL of these:
    ▸ alg='none': eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...
    ▸ alg='None': eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0...

◆ SECURITY FINDINGS
───────────────────
  [CRITICAL] (Signature) HMAC secret recovered via wordlist audit: 'secret'.
  [HIGH    ] (Claims) No 'exp' (expiration) claim — this token never expires by design.
  [MEDIUM  ] (Claims) Claim name(s) suggest sensitive data may be embedded: password_hash
```

---

## 📦 Installation

```bash
git clone https://github.com/linxploit/token-smith.git
cd token-smith
pip install -r requirements.txt
```

Requires **Python 3.8+**. The `cryptography` package is required for RSA/EC signature verification and algorithm-confusion forgery.

---

## 🚀 Usage

### Analyze a token

```bash
python3 tokensmith.py -T eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Analyze a token from a file

```bash
python3 tokensmith.py --token-file examples/sample_token.txt
```

*(That example file is the well-known public jwt.io debugger token — run it and watch TokenSmith recover its famously weak secret in one attempt, as a working demo.)*

### Audit against a custom wordlist

```bash
python3 tokensmith.py -T eyJ... --wordlist examples/sample_wordlist.txt
```

### Test algorithm-confusion with the server's public key

```bash
python3 tokensmith.py -T eyJ... --public-key server_public_key.pem
```

### Replay forged tokens against a real endpoint (opt-in, authorized targets only)

```bash
python3 tokensmith.py -T eyJ... --live-test --verify-url https://api.example.com/me
```

### Save a full report

```bash
python3 tokensmith.py -T eyJ... -o report.json
```

### Full option reference

```bash
python3 tokensmith.py --help
```

| Flag | Description |
|---|---|
| `-T`, `--token` | The JWT to analyze |
| `--token-file` | Read the JWT from a file instead |
| `--wordlist` | Custom wordlist for the weak-secret audit |
| `--public-key` | PEM file with the server's public key |
| `--no-crack` | Skip the weak-secret audit |
| `--live-test` | Actually send forged tokens to `--verify-url` |
| `--verify-url` | Endpoint to replay forged tokens against |
| `--auth-header` | Header name for `--live-test` (default: `Authorization`) |
| `-t`, `--timeout` | Live-test request timeout in seconds (default: `10`) |
| `-o`, `--output` | Save report to `.json` or `.csv` |
| `-v`, `--verbose` | Show full forged tokens instead of truncated previews |
| `--yes` | Skip the authorization prompt for `--live-test` |
| `--no-banner` | Suppress the banner |
| `--version` | Print version info and exit |

---

## 🧭 Understanding the two forgery techniques

**`alg:none`** — the JWT spec allows an unsigned token (`alg: none`). Some libraries, when configured carelessly (or by default in older versions), will accept *any* token declaring this algorithm without checking a signature at all. TokenSmith generates the common case variants because some vulnerable implementations only check the string `"none"` case-sensitively.

**Algorithm confusion (RS256→HS256)** — if a verifier is written to just read whatever `alg` a token claims and then look up "the key" for that algorithm — without pinning the expected algorithm server-side — an attacker who has the server's RSA **public** key (often not secret at all; sometimes published, sometimes recoverable) can sign a new token with `alg: HS256`, using that public key's raw bytes as the HMAC secret. A careless verifier that reuses the same "key" variable for both RS256 verification and HS256 verification will accept it. This is a well-documented, industry-standard finding class — TokenSmith's forgery generation for it is cryptographically validated in the test suite.

> ⚠️ **A forged token being generated is not proof it will be accepted.** Confirm behavior against your own verifier code, or use `--live-test` against an authorized target, before treating this as a confirmed finding.

---

## ⚖️ Responsible use

TokenSmith's default mode performs **zero network requests** — decoding, claim analysis, secret cracking, and forgery generation are all local computation on a token string you provide. The only feature that touches a network is `--live-test`, and it requires:

- An explicit `--verify-url`
- Explicit `--live-test`
- Confirming authorization at the prompt (or passing `--yes` for your own automated pipelines)

Only use `--live-test` against systems you **own** or have **explicit permission** to assess. If a forged token is genuinely accepted by a live system, follow responsible disclosure — don't use the access it grants for anything beyond confirming the finding. You are solely responsible for how you use this tool and for complying with all applicable laws and the terms of any authorization you've been granted.

---

## 🛠️ Project structure

```
token-smith/
├── tokensmith.py            # Main executable — the tool itself
├── requirements.txt            # Python dependencies
├── examples/
│   ├── sample_token.txt           # The public jwt.io example token (weak-secret demo)
│   └── sample_wordlist.txt        # Example custom wordlist format
├── tests/
│   └── test_tokensmith.py         # Unit tests, including a cryptographic forgery proof
├── LICENSE                     # MIT License
└── README.md                    # You are here
```

---

## 🤝 Contributing

Issues and pull requests are welcome — an expanded default wordlist, additional header risk heuristics, and support for more signature algorithms are all great contributions.

---

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">

### Made by **Mindless**
**Founder & CEO of [Linxploit](https://linxploit.com)**

🌐 [linxploit.com](https://linxploit.com) &nbsp;·&nbsp; 👤 [linxploit.com/founder](https://linxploit.com/founder)

</div>
