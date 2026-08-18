"""Entry point for the TP-Link VX800v Prometheus exporter."""

from __future__ import annotations

import logging
import signal
import sys
import time

from prometheus_client import start_http_server

from collector import RouterSession, collect_metrics, reset_poll_failure_counter
from config import (
    EXIT_AFTER_CONSECUTIVE_INIT_FAILURES,
    EXIT_AFTER_SECONDS_WITHOUT_POLL_SUCCESS,
    METRICS_PORT,
    RECONNECT_AFTER_POLL_FAILURES,
    RECONNECT_BACKOFF_MAX_SECONDS,
    RECONNECT_BACKOFF_SECONDS,
    SCRAPE_INTERVAL,
    TPLINK_ROUTER_HOST,
    device_name,
    get_password,
    setup_logging,
)
from version import get_version

setup_logging()
logger = logging.getLogger(__name__)

_shutdown = False


def _fatal_no_poll_success(start_monotonic: float, last_poll_success: float | None) -> None:
    limit = EXIT_AFTER_SECONDS_WITHOUT_POLL_SUCCESS
    if limit <= 0:
        return
    now = time.monotonic()
    reference = last_poll_success if last_poll_success is not None else start_monotonic
    if now - reference >= limit:
        logger.critical(
            "No successful poll within %d seconds; exiting for process restart",
            limit,
        )
        sys.exit(1)


def _sleep_until_shutdown(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while not _shutdown and time.monotonic() < deadline:
        time.sleep(min(1.0, deadline - time.monotonic()))


def main_loop() -> None:
    start_monotonic = time.monotonic()
    last_poll_success: float | None = None
    reconnect_backoff = float(RECONNECT_BACKOFF_SECONDS)
    init_failures = 0
    session: RouterSession | None = None

    while not _shutdown:
        if session is None:
            try:
                logger.info("Connecting to router at %s", TPLINK_ROUTER_HOST)
                session = RouterSession()
                session.connect()
            except Exception as exc:
                init_failures += 1
                logger.error("Failed to connect to router: %s", exc)
                session = None
                if (
                    EXIT_AFTER_CONSECUTIVE_INIT_FAILURES > 0
                    and init_failures >= EXIT_AFTER_CONSECUTIVE_INIT_FAILURES
                ):
                    logger.critical(
                        "Exiting after %d consecutive init failures",
                        init_failures,
                    )
                    sys.exit(1)
                _sleep_until_shutdown(reconnect_backoff)
                reconnect_backoff = min(reconnect_backoff * 2, float(RECONNECT_BACKOFF_MAX_SECONDS))
                continue

            init_failures = 0
            reconnect_backoff = float(RECONNECT_BACKOFF_SECONDS)
            reset_poll_failure_counter()

        assert session is not None
        poll_result = collect_metrics(session)
        _fatal_no_poll_success(start_monotonic, last_poll_success)

        if poll_result.ok:
            last_poll_success = time.monotonic()
        elif poll_result.recycle_connection:
            logger.warning(
                "Recycling router connection after %d consecutive poll failures (threshold %d)",
                poll_result.consecutive_poll_failures,
                RECONNECT_AFTER_POLL_FAILURES,
            )
            session.disconnect()
            session = None
            reset_poll_failure_counter()
            _sleep_until_shutdown(float(RECONNECT_BACKOFF_SECONDS))
            continue

        _sleep_until_shutdown(float(SCRAPE_INTERVAL))
        _fatal_no_poll_success(start_monotonic, last_poll_success)


def main() -> None:
    if not get_password():
        logger.error("TPLINK_ROUTER_PASSWORD environment variable is required")
        sys.exit(1)

    logger.info("Starting TP-Link VX800v Exporter v%s", get_version())
    logger.info("Router Host: %s", TPLINK_ROUTER_HOST)
    logger.info("Device Label: %s", device_name())
    logger.info("Metrics Port: %d", METRICS_PORT)
    logger.info("Scrape Interval: %ds", SCRAPE_INTERVAL)
    if RECONNECT_AFTER_POLL_FAILURES > 0:
        logger.info(
            "Reconnect after %d consecutive poll failures; backoff %ds–%ds",
            RECONNECT_AFTER_POLL_FAILURES,
            RECONNECT_BACKOFF_SECONDS,
            RECONNECT_BACKOFF_MAX_SECONDS,
        )
    if EXIT_AFTER_SECONDS_WITHOUT_POLL_SUCCESS > 0:
        logger.info(
            "Will exit if no successful poll for %ds",
            EXIT_AFTER_SECONDS_WITHOUT_POLL_SUCCESS,
        )
    if EXIT_AFTER_CONSECUTIVE_INIT_FAILURES > 0:
        logger.info(
            "Will exit after %d consecutive init failures",
            EXIT_AFTER_CONSECUTIVE_INIT_FAILURES,
        )

    start_http_server(METRICS_PORT)
    logger.info("Prometheus metrics server started on port %d", METRICS_PORT)

    def shutdown_handler(sig, frame):
        global _shutdown
        logger.info("Received signal %s, shutting down...", sig)
        _shutdown = True

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        main_loop()
    finally:
        logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
