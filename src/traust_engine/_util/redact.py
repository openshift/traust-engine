"""Structural write-time redaction.

Single-source secret patterns for every harness report writer.
Promoted from generate-team-report's Step-7 packaging redaction (our own
in-house patterns) and extended with the classes we lacked: Luhn-gated
payment card numbers, US SSNs, Azure/GCP key material, and URL-embedded
credentials. Convention: keep the first 5 characters, replace the rest
with ``...REDACTED`` so evidence stays traceable without being usable.

Two entry points:
  redact_text(text)   -> (redacted_text, hits)   — write-time scrubbing
  scan_text(text)     -> hits                    — detection only, used
                          by validate_report --strict to REJECT reports
                          that carry unredacted secrets

`hits` is a list of {"category", "match_prefix"} — never the full
secret.
"""

from __future__ import annotations

import re

_KEEP = 5
_MARK = "...REDACTED"

# (category, compiled regex) — value-capturing group 1 optional; when
# present only group 1 is replaced (assignment-style patterns)
PATTERNS: list[tuple[str, re.Pattern, bool]] = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{12,}"), False),
    ("github-token", re.compile(r"gh[posru]_[a-zA-Z0-9]{30,}"), False),
    ("github-pat", re.compile(r"github_pat_[a-zA-Z0-9_]{20,}"), False),
    ("gitlab-token", re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}"), False),
    ("slack-token", re.compile(r"xox[bpsa]-[a-zA-Z0-9\-]{10,}"), False),
    ("llm-api-key", re.compile(r"sk-[a-zA-Z0-9]{20,}"), False),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), False),
    ("bearer-token", re.compile(r"Bearer\s+([a-zA-Z0-9._\-]{20,})"), True),
    (
        "jwt",
        re.compile(
            r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\."
            r"[a-zA-Z0-9_\-]{10,}"
        ),
        False,
    ),
    (
        "password-assignment",
        re.compile(r"(?:password|passwd)\s*[:=]\s*\\?['\"]([^'\"\\]{8,})\\?['\"]", re.IGNORECASE),
        True,
    ),
    (
        "secret-assignment",
        re.compile(r"secret\s*[:=]\s*\\?['\"]([^'\"\\]{8,})\\?['\"]", re.IGNORECASE),
        True,
    ),
    (
        "token-assignment",
        re.compile(r"token\s*[:=]\s*\\?['\"]([^'\"\\]{8,})\\?['\"]", re.IGNORECASE),
        True,
    ),
    (
        "apikey-assignment",
        re.compile(r"api[_-]?key\s*[:=]\s*\\?['\"]([^'\"\\]{8,})\\?['\"]", re.IGNORECASE),
        True,
    ),
    # --- classes added by plan P2 (we lacked these) -------------------
    ("url-credentials", re.compile(r"://[A-Za-z0-9._%+-]+:([^@/\s'\"]{6,})@"), True),
    ("us-ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), False),
    ("azure-client-secret", re.compile(r"\b[a-zA-Z0-9~_.\-]{3}8Q~[a-zA-Z0-9~_.\-]{30,}\b"), False),
    ("gcp-sa-key", re.compile(r'"private_key_id"\s*:\s*"([a-f0-9]{40})"'), True),
]

# classes where a match is near-certainly a real credential (structured
# vendor token formats). Heuristic classes (assignments, SSN, PAN,
# url-credentials) can legitimately appear in quoted audit evidence —
# calibrated 2026-07-24: 400-report corpus dry run had 0 high-confidence
# hits and 14 heuristic hits, all evidence quotes.
HIGH_CONFIDENCE = frozenset(
    {
        "aws-access-key",
        "github-token",
        "github-pat",
        "gitlab-token",
        "slack-token",
        "google-api-key",
        "jwt",
        "pem-private-key",
        "azure-client-secret",
        "gcp-sa-key",
    }
)

_PEM = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE "
    r"KEY-----)",
    re.DOTALL,
)

# candidate PANs: 13-19 digits, optionally space/dash separated
_PAN_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _redact_value(value: str) -> str:
    return value[:_KEEP] + _MARK


def _apply(text: str, collect: list, replace: bool) -> str:
    for category, rx, group1 in PATTERNS:

        def _sub(m, _c=category, _g=group1):
            whole = m.group(0)
            val = m.group(1) if _g and m.lastindex else whole
            if _MARK in whole:
                return whole  # already redacted
            collect.append({"category": _c, "match_prefix": val[:_KEEP]})
            if not replace:
                return whole
            red = _redact_value(val)
            return whole.replace(val, red) if _g and m.lastindex else red

        text = rx.sub(_sub, text)

    def _pem(m):
        collect.append({"category": "pem-private-key", "match_prefix": "-----"})
        if not replace:
            return m.group(0)
        return f"{m.group(1)}\n[PRIVATE KEY MATERIAL REDACTED]\n{m.group(3)}"

    text = _PEM.sub(_pem, text)

    def _pan(m):
        digits = re.sub(r"[ -]", "", m.group(0))
        if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
            return m.group(0)  # not a card number — leave untouched
        collect.append({"category": "payment-card", "match_prefix": digits[:_KEEP]})
        if not replace:
            return m.group(0)
        return _redact_value(digits)

    text = _PAN_CANDIDATE.sub(_pan, text)
    return text


def redact_text(text: str) -> tuple[str, list[dict]]:
    """Redact in place; returns (clean_text, hits)."""
    hits: list[dict] = []
    return _apply(text, hits, replace=True), hits


def scan_text(text: str) -> list[dict]:
    """Detect only — powers validate_report --strict rejection."""
    hits: list[dict] = []
    _apply(text, hits, replace=False)
    return hits
