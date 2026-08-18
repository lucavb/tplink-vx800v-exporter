"""Poll cycle and router session management."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from auth import (
    collect_router_metrics,
    connect_router,
    probe_unauthenticated,
    resolve_username,
)
from config import (
    RECONNECT_AFTER_POLL_FAILURES,
    STALE_AFTER_FAILURES,
    TPLINK_ROUTER_CLIENT,
    TPLINK_ROUTER_HOST,
    TPLINK_ROUTER_TIMEOUT,
    TPLINK_ROUTER_USER,
    TPLINK_ROUTER_VERIFY_SSL,
    TPLINK_TRY_USERS,
    device_name,
    get_password,
)
from logging_utils import ProbeLog, redact
from metrics import reset_dynamic_metrics, tplink_up, update_metrics

logger = logging.getLogger(__name__)

_consecutive_failures = 0


def reset_poll_failure_counter() -> None:
    global _consecutive_failures
    _consecutive_failures = 0


@dataclass(frozen=True)
class PollResult:
    ok: bool
    recycle_connection: bool
    consecutive_poll_failures: int = 0


class RouterSession:
    """Holds an authenticated router client across poll cycles."""

    def __init__(self) -> None:
        self.client: Any | None = None
        self.client_class: str = "unknown"
        self.model: str | None = None
        self.login_flags: dict[str, str] | None = None
        self._log = ProbeLog(logger.isEnabledFor(logging.DEBUG))

    def connect(self) -> None:
        password = get_password()
        if not password:
            raise RuntimeError("TPLINK_ROUTER_PASSWORD environment variable is required")

        unauth = probe_unauthenticated(
            TPLINK_ROUTER_HOST,
            TPLINK_ROUTER_VERIFY_SSL,
            TPLINK_ROUTER_TIMEOUT,
            self._log,
        )
        if not unauth.get("reachable"):
            raise RuntimeError(unauth.get("error") or "router unreachable")

        self.model = unauth.get("model")
        username = resolve_username(self.model, TPLINK_ROUTER_USER)
        self.login_flags = unauth.get("login_flags")

        try_users = None
        if TPLINK_TRY_USERS:
            try_users = [part.strip() for part in TPLINK_TRY_USERS.split(",")]

        busy = (unauth.get("cgis", {}).get("/cgi/getBusy") or {}).get("vars", {})
        logout_first = busy.get("isLogined") == "1"

        self.client, self.client_class = connect_router(
            TPLINK_ROUTER_HOST,
            password,
            username,
            TPLINK_ROUTER_VERIFY_SSL,
            TPLINK_ROUTER_TIMEOUT,
            self._log,
            model=self.model,
            forced_client=TPLINK_ROUTER_CLIENT,
            logout_first=logout_first,
            login_flags=self.login_flags,
            try_users=try_users,
        )
        logger.info(
            "Connected to %s (model=%s, client=%s)",
            TPLINK_ROUTER_HOST,
            self.model,
            self.client_class,
        )

    def disconnect(self) -> None:
        self.client = None
        self.client_class = "unknown"

    def poll(self) -> dict[str, Any]:
        if self.client is None:
            raise RuntimeError("not connected")
        return collect_router_metrics(self.client, self._log)


def collect_metrics(session: RouterSession) -> PollResult:
    """Poll router and update Prometheus metrics."""
    global _consecutive_failures
    device = device_name()

    try:
        data = session.poll()
        _consecutive_failures = 0
        tplink_up.labels(device=device).set(1)
        update_metrics(device, data, client_class=session.client_class)
        logger.debug("Updated metrics for device %s", device)
        return PollResult(ok=True, recycle_connection=False, consecutive_poll_failures=0)
    except Exception as exc:
        _consecutive_failures += 1
        logger.error(
            "Error polling router %s (failure %d/%d): %s",
            TPLINK_ROUTER_HOST,
            _consecutive_failures,
            STALE_AFTER_FAILURES,
            redact(str(exc)),
        )
        tplink_up.labels(device=device).set(0)

        if STALE_AFTER_FAILURES > 0 and _consecutive_failures >= STALE_AFTER_FAILURES:
            logger.warning("Resetting dynamic metrics after %d failures", _consecutive_failures)
            reset_dynamic_metrics(device)

        recycle = (
            RECONNECT_AFTER_POLL_FAILURES > 0
            and _consecutive_failures >= RECONNECT_AFTER_POLL_FAILURES
        )
        return PollResult(
            ok=False,
            recycle_connection=recycle,
            consecutive_poll_failures=_consecutive_failures,
        )
