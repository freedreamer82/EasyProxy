"""Cross-extractor renewal of signed CDN tokens.

The proxy, not the extractor, owns the token lifecycle:

* every successful extraction is recorded per ``stream_key`` together with the
  routing needed to run it again (``_record_stream_token``);
* the deadline is read from the signed URL (``services.token_expiry``) or from
  the optional ``token_expires_at`` field an extractor may return;
* manifest requests close to the deadline trigger a **proactive** re-extract
  (``_token_refresh_due`` + ``_renew_stream_tokens``);
* upstream errors that look like an expired token trigger a **reactive**
  re-extract (``_is_token_expiry_status``);
* renewals are single-flight per stream (``asyncio.Lock``) and their outcome is
  stored in ``_renewed_cdn_tokens`` so every later segment/variant URL is
  rewritten in place (``_apply_renewed_token``) without extracting again.

Everything is keyed by ``stream_key``, which the manifest rewriter already
propagates to every HLS and DASH relay URL, so the mechanism works for any
extractor without changes on its side.
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse

import aiohttp

import config_store
from services.proxy_shared import logger
from services.token_expiry import (
    is_expiry_status,
    parse_token_expiry,
    split_base_and_query,
)

TOKEN_REFRESH_DEFAULT_ENABLED = True
TOKEN_REFRESH_DEFAULT_MARGIN = 30
TOKEN_REFRESH_MIN_MARGIN = 5
TOKEN_REFRESH_MAX_MARGIN = 300


class HLSProxyTokenRefreshMixin:
    """Mixed into ``HLSProxy``; relies on ``get_extractor`` and ``_stream_key_for_url``."""

    #: entries idle for longer than this are dropped by the cleanup task
    TOKEN_META_IDLE_SECONDS = 300.0
    #: never re-extract the same stream more often than this
    TOKEN_RENEW_MIN_INTERVAL = 8.0
    #: callers that waited on a renewal in progress reuse a result this young
    TOKEN_RENEW_SHARED_WINDOW = 5.0
    #: absolute floor between two extractions of the same stream (loop guard)
    TOKEN_RENEW_HARD_FLOOR = 1.0

    # ------------------------------------------------------------------ config
    @staticmethod
    def _token_refresh_enabled() -> bool:
        try:
            return bool(config_store.get("token_refresh_enabled", TOKEN_REFRESH_DEFAULT_ENABLED))
        except Exception:
            return TOKEN_REFRESH_DEFAULT_ENABLED

    @staticmethod
    def _token_refresh_margin() -> float:
        try:
            raw = config_store.get("token_refresh_margin_sec", TOKEN_REFRESH_DEFAULT_MARGIN)
            margin = float(raw if raw is not None else TOKEN_REFRESH_DEFAULT_MARGIN)
        except (TypeError, ValueError):
            margin = float(TOKEN_REFRESH_DEFAULT_MARGIN)
        return max(TOKEN_REFRESH_MIN_MARGIN, min(TOKEN_REFRESH_MAX_MARGIN, margin))

    # ------------------------------------------------------------------- state
    def _token_state(self) -> dict:
        state = getattr(self, "_token_refresh_state", None)
        if state is None:
            state = self._token_refresh_state = {
                "meta": {},      # stream_key -> dict (deadline, orig_url, routing, ...)
                "locks": {},     # lock_key -> asyncio.Lock
                "aliases": {},   # stream_key -> [old base dirs the player may still use]
                "tasks": {},     # stream_key -> asyncio.Task of a proactive renewal in flight
                "queries": {},   # stream_key -> (old_query, new_query)
                "stats": {
                    "proactive": 0,
                    "reactive": 0,
                    "failed": 0,
                    "unchanged": 0,
                    "last_event": None,
                    "last_reason": None,
                    "last_stream": None,
                    "last_error": None,
                },
            }
        if not hasattr(self, "_renewed_cdn_tokens"):
            self._renewed_cdn_tokens = {}
        if not hasattr(self, "_renewed_cdn_token_atimes"):
            self._renewed_cdn_token_atimes = {}
        return state

    def _token_refresh_report(self) -> dict:
        state = self._token_state()
        report = dict(state["stats"])
        report["enabled"] = self._token_refresh_enabled()
        report["margin_sec"] = self._token_refresh_margin()
        report["tracked_streams"] = len(state["meta"])
        now = time.time()
        report["expiring_soon"] = sum(
            1 for m in state["meta"].values()
            if m.get("deadline") and m["deadline"] - now <= self._token_refresh_margin()
        )
        return report

    def _cleanup_token_refresh_state(self, now: float | None = None, force: bool = False) -> None:
        """Drop idle renewal state; mirrors the CDN-token cleanup in proxy_core.

        Cheap enough to call from the request path: it is throttled to one
        sweep every 15 seconds unless ``force`` is set.
        """
        now = now if now is not None else time.time()
        state = self._token_state()
        if not force and now - state.get("last_cleanup", 0.0) < 15.0:
            return
        state["last_cleanup"] = now
        idle = self.TOKEN_META_IDLE_SECONDS
        for key in [k for k, m in state["meta"].items() if now - m.get("atime", now) > idle]:
            state["meta"].pop(key, None)
            lock = state["locks"].get(key)
            if lock is not None and not lock.locked():
                state["locks"].pop(key, None)
        stale = [k for k, t in self._renewed_cdn_token_atimes.items() if now - t > idle]
        for key in stale:
            self._renewed_cdn_tokens.pop(key, None)
            self._renewed_cdn_token_atimes.pop(key, None)
            state["aliases"].pop(key, None)
            state["queries"].pop(key, None)
        for key in [k for k, lock in state["locks"].items() if not lock.locked() and k not in state["meta"]]:
            state["locks"].pop(key, None)

    # ---------------------------------------------------------------- statuses
    def _is_token_expiry_status(self, status: int, url: str = "") -> bool:
        """403 always (legacy behaviour); the wider set only when enabled."""
        if not self._token_refresh_enabled():
            return status == 403
        return is_expiry_status(status, url)

    # --------------------------------------------------------------- tracking
    def _record_stream_token(
        self,
        stream_key: str | None,
        result: dict | None,
        *,
        orig_url: str | None,
        request_headers: dict | None = None,
        bypass_warp: bool | None = None,
        forced_proxy: str | None = None,
        force_direct: bool | None = None,
        extractor_key: str | None = None,
        host: str | None = None,
    ) -> float | None:
        """Remember how to re-run this extraction and when its URL expires."""
        if not stream_key or not result:
            return None
        destination_url = result.get("destination_url")
        if not destination_url or not orig_url:
            return None
        now = time.time()
        deadline = None
        explicit = result.get("token_expires_at")
        if explicit is not None:
            try:
                explicit = float(explicit)
                if explicit > 1e11:
                    explicit /= 1000.0
                if explicit > now:
                    deadline = explicit
            except (TypeError, ValueError):
                deadline = None
        if deadline is None:
            deadline = parse_token_expiry(destination_url, now=now)
            if deadline is not None and deadline <= now:
                deadline = None

        state = self._token_state()
        previous = state["meta"].get(stream_key) or {}
        meta = {
            "deadline": deadline,
            "destination_url": destination_url,
            "orig_url": orig_url,
            "request_headers": dict(request_headers or previous.get("request_headers") or {}),
            "bypass_warp": bool(bypass_warp) if bypass_warp is not None else previous.get("bypass_warp", False),
            "forced_proxy": forced_proxy if forced_proxy is not None else previous.get("forced_proxy"),
            "force_direct": bool(force_direct) if force_direct is not None else previous.get("force_direct", False),
            "extractor_key": extractor_key or previous.get("extractor_key"),
            "host": host or previous.get("host"),
            "atime": now,
            "recorded_at": now,
            "renewed_at": previous.get("renewed_at", 0.0),
            "last_result": previous.get("last_result"),
            "proactive_disabled": False,
        }
        state["meta"][stream_key] = meta
        if deadline:
            logger.debug(
                "🔑 Token tracked for stream_key=%s: expires in %.0fs (%s)",
                stream_key[:8],
                deadline - now,
                extractor_key or "generic",
            )
        return deadline

    def _token_refresh_due(self, stream_key: str | None) -> bool:
        """True when the tracked URL is about to expire and a renewal is sensible."""
        if not stream_key or not self._token_refresh_enabled():
            return False
        meta = self._token_state()["meta"].get(stream_key)
        if not meta:
            return False
        now = time.time()
        meta["atime"] = now
        deadline = meta.get("deadline")
        if not deadline or meta.get("proactive_disabled"):
            return False
        if now - meta.get("renewed_at", 0.0) < self.TOKEN_RENEW_MIN_INTERVAL:
            return False
        return now >= deadline - self._token_refresh_margin()

    # ------------------------------------------------------------ URL mapping
    def _store_renewed_token(self, stream_key: str | None, old_url: str, new_url: str) -> None:
        """Map the directory of ``old_url`` onto ``new_url`` for later relay requests."""
        if not stream_key or not old_url or not new_url or old_url == new_url:
            return
        state = self._token_state()
        old_b, old_q = split_base_and_query(old_url)
        new_b, new_q = split_base_and_query(new_url)
        aliases = list(state["aliases"].get(stream_key) or [])
        previous = self._renewed_cdn_tokens.get(stream_key)
        if previous:
            # Chained renewal: the player still holds URLs built from the very
            # first base, so keep every base seen so far as an alias.
            for base in (previous[0], previous[1]):
                if base and base not in aliases:
                    aliases.append(base)
        if old_b not in aliases:
            aliases.append(old_b)
        aliases = [a for a in aliases if a != new_b]
        self._renewed_cdn_tokens[stream_key] = (old_b, new_b, new_q)
        self._renewed_cdn_token_atimes[stream_key] = time.time()
        state["aliases"][stream_key] = aliases[-8:]
        state["queries"][stream_key] = (old_q, new_q)

    def _apply_renewed_token(self, stream_key: str | None, url: str) -> str:
        """Rewrite ``url`` with the renewed base/query recorded for ``stream_key``."""
        if not stream_key or not url:
            return url
        entry = self._renewed_cdn_tokens.get(stream_key)
        if not entry:
            return url
        old_b, new_b, new_q = entry
        state = self._token_state()
        bases = [old_b] + [a for a in state["aliases"].get(stream_key, []) if a != old_b]
        rewritten = None
        for base in bases:
            if base and url.startswith(base):
                rest = url[len(base):].split("?", 1)[0]
                rewritten = new_b + rest + new_q
                break
        if rewritten is None:
            # Same path on a different edge host (CDN rotation between extractions).
            try:
                cur = urllib.parse.urlsplit(url)
                for base in bases:
                    ob = urllib.parse.urlsplit(base)
                    if ob.path and ob.path != "/" and cur.path.startswith(ob.path) and cur.netloc != ob.netloc:
                        rest = cur.path[len(ob.path):]
                        rewritten = new_b + rest + new_q
                        break
            except ValueError:
                rewritten = None
        if rewritten is None and new_q:
            # Segment carries the same (stale) query as the old master: swap it.
            old_q, _ = state["queries"].get(stream_key, ("", ""))
            if old_q and "?" in url and url.endswith(old_q):
                rewritten = url.split("?", 1)[0] + new_q
        if rewritten is None or rewritten == url:
            return url
        self._renewed_cdn_token_atimes[stream_key] = time.time()
        return rewritten

    def _already_renewed(self, stream_key: str | None, failed_url: str | None) -> bool:
        """Was ``failed_url`` already built with the latest renewed token?

        If so, handing the caller the cached renewal would just replay the same
        failing request: a genuine re-extraction is needed.
        """
        if not stream_key or not failed_url:
            return False
        entry = self._renewed_cdn_tokens.get(stream_key)
        if not entry:
            return False
        _old_b, new_b, new_q = entry
        if not new_b or not failed_url.startswith(new_b):
            return False
        if new_q:
            current_q = ("?" + failed_url.split("?", 1)[1]) if "?" in failed_url else ""
            return current_q == new_q
        return True

    # ------------------------------------------------------------- background
    def _schedule_proactive_renewal(self, stream_key: str | None, **routing) -> None:
        """Start one proactive renewal for ``stream_key`` without waiting for it.

        One task per stream: while it runs, every manifest request keeps being
        served on the current token (``_token_refresh_due`` stays true until
        ``renewed_at`` moves, so this is what stops a request per reload). Its
        outcome lands in ``_renewed_cdn_tokens`` like any other renewal and the
        next reload is rewritten onto the new token.
        """
        if not stream_key:
            return
        tasks = self._token_state()["tasks"]
        running = tasks.get(stream_key)
        if running is not None and not running.done():
            return

        async def _run():
            try:
                await self._renew_stream_tokens(stream_key, "proactive", **routing)
            except Exception as exc:  # never let a background renewal die silently
                logger.warning("Token proactive renewal task failed for stream_key=%s: %s", stream_key[:8], exc)
            finally:
                if tasks.get(stream_key) is task:
                    tasks.pop(stream_key, None)

        task = asyncio.create_task(_run())
        tasks[stream_key] = task

    # ------------------------------------------------------ player-side URLs
    def _restore_client_token(
        self,
        manifest_text: str,
        *,
        upstream_url: str,
        client_url: str,
        stream_key: str | None = None,
    ) -> tuple[str, str]:
        """Rewrite a playlist fetched on a renewed token back onto the URL the
        player holds, so the URIs it sees never change across a renewal.

        Returns ``(text, base_url)``: the text with the upstream token/query and
        base directory replaced by the client's, and the client URL to resolve
        relative URIs against. The segment relay maps every such URL forward
        again on fetch, so nothing upstream ever sees the old token.
        """
        if not manifest_text or not upstream_url or not client_url or upstream_url == client_url:
            return manifest_text, upstream_url
        up_b, up_q = split_base_and_query(upstream_url)
        cl_b, cl_q = split_base_and_query(client_url)
        text = manifest_text
        if up_q and cl_q and up_q != cl_q:
            text = text.replace(up_q, cl_q)
        if up_b and cl_b and up_b != cl_b:
            text = text.replace(up_b, cl_b)
        if text != manifest_text:
            logger.debug(
                "🔁 Playlist written on the player's own token for stream_key=%s",
                (stream_key or "")[:8],
            )
        return text, client_url

    # ---------------------------------------------------------------- warm-up
    async def _warm_renewed_master(
        self,
        meta: dict,
        new_url: str,
        headers: dict,
        *,
        disable_ssl: bool = False,
        log_key: str = "",
    ) -> None:
        """Fetch the renewed master once, so the CDN accepts the token elsewhere.

        bluetier (freeshot) answered 404 to the variant playlist retried with a
        freshly renewed token, while the same token on ``index.m3u8`` answered
        200 (2026-10-19 16:11 UTC, stream_key 4e204e11): the token is honoured
        on variants and segments only after the master has been fetched with
        it. A relay never fetches the master again - the player holds the
        variant URL - so it is done here, once, before anything is retried on
        the new token. Best effort: a failure here is logged and the renewal
        stands, the retry then tells.
        """
        try:
            session, _route = await self._get_proxy_session(
                new_url,
                bypass_warp=bool(meta.get("bypass_warp", False)),
                forced_proxy=meta.get("forced_proxy"),
                force_direct=bool(meta.get("force_direct", False)),
            )
            async with session.get(
                new_url, headers=dict(headers or {}), ssl=not disable_ssl,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                await resp.content.read(65536)
                logger.info(
                    "🔥 Token warm-up: master fetched with the renewed token (status=%s) for stream_key=%s",
                    resp.status,
                    log_key,
                )
        except Exception as exc:
            logger.warning("Token warm-up failed for stream_key=%s: %s", log_key, exc)

    # ---------------------------------------------------------------- renewal
    async def _renew_stream_tokens(
        self,
        stream_key: str | None,
        reason: str,
        *,
        orig_url: str | None = None,
        request_headers: dict | None = None,
        bypass_warp: bool | None = None,
        forced_proxy: str | None = None,
        force_direct: bool | None = None,
        current_url: str | None = None,
        extractor_key: str | None = None,
        host: str | None = None,
        failed_url: str | None = None,
    ) -> dict | None:
        """Re-extract the source for ``stream_key`` and publish the renewed URL.

        Returns the fresh extractor result (``destination_url``, headers,
        routing fields, captured manifests) or ``None`` when nothing could be
        renewed. Concurrent callers for the same stream share one extraction.
        ``failed_url`` (reactive path) is the upstream URL that just failed: when
        it already carries the latest renewed token the cached renewal is not
        reused and a new extraction runs.
        """
        state = self._token_state()
        meta = state["meta"].get(stream_key) if stream_key else None
        meta = meta or {}
        orig_url = orig_url or meta.get("orig_url")
        if not orig_url:
            return None
        lock_key = stream_key or self._stream_key_for_url(orig_url) or orig_url
        lock = state["locks"].get(lock_key)
        if lock is None:
            lock = state["locks"][lock_key] = asyncio.Lock()

        if lock.locked():
            # Another request is already renewing this stream: wait for it and
            # reuse its outcome instead of hammering the provider.
            async with lock:
                pass
            meta = state["meta"].get(stream_key, meta) if stream_key else meta
            last = meta.get("last_result")
            age = time.time() - meta.get("renewed_at", 0.0)
            if last and age <= self.TOKEN_RENEW_SHARED_WINDOW and not self._already_renewed(stream_key, failed_url):
                return last
            if last and age < self.TOKEN_RENEW_HARD_FLOOR:
                return last
            if not last:
                return None
            # The renewed token itself failed: fall through and renew again.

        async with lock:
            now = time.time()
            meta = state["meta"].get(stream_key, meta) if stream_key else meta
            last = meta.get("last_result")
            age = now - meta.get("renewed_at", 0.0)
            if last and age < self.TOKEN_RENEW_MIN_INTERVAL and not self._already_renewed(stream_key, failed_url):
                # Renewed moments ago: the fresh URL is already in the mapping.
                return last
            if last and age < self.TOKEN_RENEW_HARD_FLOOR:
                return last

            # The headers recorded with the original extraction are the ones the
            # extractor was built for; the relay's upstream headers are a fallback.
            headers = dict(meta.get("request_headers") or request_headers or {})
            if bypass_warp is None:
                bypass_warp = bool(meta.get("bypass_warp", False))
            if forced_proxy is None:
                forced_proxy = meta.get("forced_proxy")
            if force_direct is None:
                force_direct = bool(meta.get("force_direct", False))
            host = host or meta.get("host")
            extractor_key = extractor_key or meta.get("extractor_key")
            # The mapping must start from the tracked master URL: the caller may
            # be relaying a variant playlist or a segment, whose directory is
            # not the one the renewed master URL replaces.
            current_url = meta.get("destination_url") or current_url
            stats = state["stats"]
            log_key = (stream_key or lock_key)[:8]

            logger.info(
                "🔄 [Token %s] Re-extracting %s for stream_key=%s",
                reason,
                orig_url[:80],
                log_key,
            )
            try:
                extractor = await self.get_extractor(orig_url, headers, host=host, bypass_warp=bypass_warp)
                if not extractor:
                    raise RuntimeError("no extractor for source URL")
                extract_kwargs = {
                    "force_refresh": True,
                    "request_headers": headers,
                    "bypass_warp": bypass_warp,
                    "proxy": forced_proxy,
                }
                if force_direct:
                    extract_kwargs["direct"] = "1"
                timeout = getattr(extractor, "REQUEST_TIMEOUT_TOTAL", 30)
                refreshed = await asyncio.wait_for(
                    extractor.extract(orig_url, **extract_kwargs), timeout=timeout
                )
            except Exception as exc:
                stats["failed"] += 1
                stats["last_event"] = time.time()
                stats["last_reason"] = f"{reason}:failed"
                stats["last_stream"] = log_key
                stats["last_error"] = str(exc)[:200]
                logger.warning(
                    "Token %s renewal failed for stream_key=%s: %s",
                    reason,
                    log_key,
                    exc,
                )
                return None

            new_url = (refreshed or {}).get("destination_url")
            if not new_url:
                stats["failed"] += 1
                stats["last_event"] = time.time()
                stats["last_reason"] = f"{reason}:empty"
                stats["last_stream"] = log_key
                return None

            unchanged = bool(current_url) and new_url == current_url
            if not unchanged:
                await self._warm_renewed_master(
                    meta, new_url, refreshed.get("request_headers") or headers,
                    disable_ssl=bool(refreshed.get("disable_ssl", False)), log_key=log_key,
                )
            if stream_key:
                if not unchanged:
                    self._store_renewed_token(stream_key, current_url, new_url)
                self._record_stream_token(
                    stream_key,
                    refreshed,
                    orig_url=orig_url,
                    request_headers=headers,
                    bypass_warp=refreshed.get("bypass_warp", bypass_warp),
                    forced_proxy=refreshed.get("selected_proxy") or forced_proxy,
                    force_direct=refreshed.get("force_direct", force_direct),
                    extractor_key=extractor_key,
                    host=host,
                )
                meta = state["meta"].get(stream_key)
                if meta is not None:
                    meta["renewed_at"] = time.time()
                    meta["last_result"] = refreshed
                    if unchanged and reason == "proactive":
                        # The extractor handed back the same signed URL: either it
                        # ignores force_refresh or the token is not renewable.
                        # Stop polling it proactively; the reactive path remains.
                        meta["proactive_disabled"] = True
            if unchanged:
                stats["unchanged"] += 1
                logger.info(
                    "ℹ️ Token %s renewal returned the same URL for stream_key=%s",
                    reason,
                    log_key,
                )
            else:
                stats[reason if reason in ("proactive", "reactive") else "reactive"] += 1
                logger.info(
                    "✅ Token %s renewal ok for stream_key=%s: %s -> %s",
                    reason,
                    log_key,
                    (current_url or "")[:60],
                    new_url[:60],
                )
            stats["last_event"] = time.time()
            stats["last_reason"] = reason
            stats["last_stream"] = log_key
            stats["last_error"] = None
            return refreshed


__all__ = [
    "HLSProxyTokenRefreshMixin",
    "TOKEN_REFRESH_DEFAULT_ENABLED",
    "TOKEN_REFRESH_DEFAULT_MARGIN",
    "TOKEN_REFRESH_MAX_MARGIN",
    "TOKEN_REFRESH_MIN_MARGIN",
]
