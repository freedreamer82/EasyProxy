"""Pure helpers to infer the lifetime of signed CDN URLs.

Nothing here touches the network or the proxy state: the functions only look at
a URL (and optionally response headers) and answer "when does this token
expire?" and "does this HTTP status look like an expired token?".  They are
shared by the HLS and DASH relays so every extractor benefits from the same
proactive/reactive refresh logic without implementing anything itself.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
from datetime import datetime, timezone

# Query parameters that usually carry an absolute expiry timestamp.
EXPIRY_QUERY_KEYS = (
    "expires",
    "expire",
    "expiry",
    "expiration",
    "exp",
    "e",
    "end",
    "validto",
    "valid_until",
    "until",
    "ttl_end",
)

# Query parameters that may carry a JWT or a structured token with an
# embedded expiry (Akamai ``st=..~exp=..`` style, ``<ts>-<hash>`` style).
TOKEN_QUERY_KEYS = (
    "token",
    "jwt",
    "auth",
    "authorization",
    "sig",
    "signature",
    "t",
    "s",
    "hdnts",
    "hdnea",
    "key",
    "secure",
    "wmsAuthSign",
)

# Upstream statuses that usually mean "signed URL no longer valid".
EXPIRY_STATUSES = frozenset({401, 403, 410, 486, 487})

# Accept expiry values that fall inside this window around "now": anything
# older than a day is probably a counter or an unrelated number, anything
# further than a week is not a short-lived CDN token.
_PAST_TOLERANCE = 86400.0
_FUTURE_LIMIT = 7 * 86400.0

_AKAMAI_EXP_RE = re.compile(r"(?:^|[~&;,])exp=(\d{9,13})(?:$|[~&;,])")
_TS_HASH_RE = re.compile(r"^(\d{9,13})[-_.:]([0-9a-zA-Z_-]{8,})$")
_HASH_TS_RE = re.compile(r"^([0-9a-zA-Z_-]{8,})[-_.:](\d{9,13})$")
_PATH_TOKEN_RE = re.compile(
    r"/(?:token|hdnts|hdnea|sig|auth|key)[-_=:][^/]{8,}/", re.IGNORECASE
)
_PATH_EXP_RE = re.compile(r"/(?:exp|expires|e)[=:](\d{9,13})(?:[/~,]|$)", re.IGNORECASE)
_PATH_AKAMAI_RE = re.compile(r"/(?:st|ip)=[^/]*?~exp=(\d{9,13})", re.IGNORECASE)


def _normalize_epoch(value: float, now: float) -> float | None:
    """Accept epoch seconds or milliseconds and reject implausible values."""
    if value <= 0:
        return None
    if value > 1e11:  # milliseconds
        value = value / 1000.0
    if value < now - _PAST_TOLERANCE or value > now + _FUTURE_LIMIT:
        return None
    return float(value)


def _parse_epoch_or_iso(raw: str, now: float) -> float | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    if raw.isdigit():
        try:
            return _normalize_epoch(float(raw), now)
        except ValueError:
            return None
    # ISO-8601 (2024-05-01T10:00:00Z / +00:00 / naive -> UTC)
    try:
        iso = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(iso)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return _normalize_epoch(parsed.timestamp(), now)
    except ValueError:
        return None


def _jwt_exp(raw: str, now: float) -> float | None:
    """Read ``exp`` from an unverified JWT (header.payload.signature)."""
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    exp = data.get("exp")
    if isinstance(exp, (int, float)):
        return _normalize_epoch(float(exp), now)
    if isinstance(exp, str) and exp.isdigit():
        return _normalize_epoch(float(exp), now)
    return None


def _piped_b64_exp(raw: str, now: float) -> float | None:
    """``base64("<channel>|<flags>|<epoch>").<hex hash>`` tokens (bluetier / freeshot).

    The signed part is plain base64 of pipe-separated fields with the expiry
    last; the hash after the dot is opaque. Seen on every ds*.bluetier.top
    link the freeshot extractor returns, where it is the whole lifetime of the
    stream: five minutes from the mint.
    """
    head = raw.split(".", 1)[0]
    if len(head) < 8:
        return None
    head += "=" * (-len(head) % 4)
    try:
        text = base64.b64decode(head.encode("ascii")).decode("utf-8")
    except Exception:
        return None
    if "|" not in text:
        return None
    tail = text.rsplit("|", 1)[1].strip()
    if not tail.isdigit():
        return None
    return _normalize_epoch(float(tail), now)


def _structured_token_exp(raw: str, now: float) -> float | None:
    """Akamai-style ``st=..~exp=..``, ``<ts>-<hash>`` and piped-base64 tokens."""
    found = _piped_b64_exp(raw, now)
    if found:
        return found
    match = _AKAMAI_EXP_RE.search(raw)
    if match:
        found = _normalize_epoch(float(match.group(1)), now)
        if found:
            return found
    match = _TS_HASH_RE.match(raw)
    if match:
        found = _normalize_epoch(float(match.group(1)), now)
        if found:
            return found
    match = _HASH_TS_RE.match(raw)
    if match:
        found = _normalize_epoch(float(match.group(2)), now)
        if found:
            return found
    return None


def parse_token_expiry(url: str, headers: dict | None = None, now: float | None = None) -> float | None:
    """Return the epoch (seconds) at which the signed ``url`` stops working.

    ``None`` means "unknown": the URL carries no recognizable expiry, so the
    caller must rely on the reactive path (upstream error -> re-extract).
    ``headers`` is optional and only used for an ``X-Token-Expires`` /
    ``X-Expires`` hint some CDNs send back.
    """
    if not url:
        return None
    now = now if now is not None else time.time()
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None

    candidates: list[float] = []
    query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=False)
    lowered = {}
    for key, value in query_items:
        lowered.setdefault(key.lower(), value)

    # 1) Explicit expiry parameters.
    for key in EXPIRY_QUERY_KEYS:
        value = lowered.get(key)
        if value is None:
            continue
        found = _parse_epoch_or_iso(value, now)
        if found:
            candidates.append(found)

    # 2) Token parameters with embedded expiry (JWT / Akamai / ts-hash).
    for key in TOKEN_QUERY_KEYS:
        value = lowered.get(key.lower())
        if not value:
            continue
        found = _jwt_exp(value, now) or _structured_token_exp(value, now)
        if found:
            candidates.append(found)

    # 3) Expiry encoded in the path (``/exp=123/``, ``/st=1~exp=2~acl=/``).
    for regex in (_PATH_EXP_RE, _PATH_AKAMAI_RE):
        for match in regex.finditer(parsed.path):
            found = _normalize_epoch(float(match.group(1)), now)
            if found:
                candidates.append(found)
    # JWT embedded as a path segment (``/token-<jwt>/`` or ``/<jwt>/``).
    for segment in parsed.path.split("/"):
        if segment.count(".") == 2 and len(segment) > 40:
            found = _jwt_exp(segment, now)
            if found:
                candidates.append(found)

    # 4) Response header hints.
    if headers:
        for name, value in headers.items():
            if name.lower() in {"x-token-expires", "x-expires", "x-url-expires"}:
                found = _parse_epoch_or_iso(str(value), now)
                if found:
                    candidates.append(found)

    if not candidates:
        return None
    # The earliest deadline wins: the stream dies as soon as any token expires.
    return min(candidates)


def looks_tokenized(url: str) -> bool:
    """True when the URL carries something that looks like a signed token."""
    if not url:
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    keys = {k.lower() for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
    if keys & {k.lower() for k in EXPIRY_QUERY_KEYS}:
        return True
    if keys & {k.lower() for k in TOKEN_QUERY_KEYS}:
        return True
    if _PATH_TOKEN_RE.search(parsed.path) or _PATH_EXP_RE.search(parsed.path) or _PATH_AKAMAI_RE.search(parsed.path):
        return True
    return False


def is_expiry_status(status: int, url: str = "") -> bool:
    """Does this upstream status plausibly mean the signed URL expired?

    403/401/410/486/487 always qualify. 404 only when the URL carries a token:
    some CDNs answer 404 instead of 403 once the signature is stale, but a
    plain 404 on an untokenized URL is a genuine missing segment.
    """
    try:
        status = int(status)
    except (TypeError, ValueError):
        return False
    if status in EXPIRY_STATUSES:
        return True
    if status == 404:
        return looks_tokenized(url)
    return False


def split_base_and_query(url: str) -> tuple[str, str]:
    """``(directory_with_trailing_slash, query_with_leading_question_mark)``."""
    if not url:
        return "", ""
    path_part, _, query = url.partition("?")
    base_dir = path_part.rsplit("/", 1)[0] + "/"
    return base_dir, ("?" + query) if query else ""


__all__ = [
    "EXPIRY_QUERY_KEYS",
    "EXPIRY_STATUSES",
    "TOKEN_QUERY_KEYS",
    "is_expiry_status",
    "looks_tokenized",
    "parse_token_expiry",
    "split_base_and_query",
]
