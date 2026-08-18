import logging
import os
from urllib.parse import urlparse

DEFAULT_HOST = "https://192.168.1.1"
DEFAULT_TIMEOUT = 60


def setup_logging() -> logging.Logger:
    debug = os.environ.get("TPLINK_DEBUG", "").lower() in ("1", "true")
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    return logging.getLogger(__name__)


def env_bool(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


TPLINK_ROUTER_HOST = os.environ.get("TPLINK_ROUTER_HOST", DEFAULT_HOST)
TPLINK_ROUTER_PASSWORD = os.environ.get("TPLINK_ROUTER_PASSWORD")
TPLINK_ROUTER_USER = os.environ.get("TPLINK_ROUTER_USER")
TPLINK_ROUTER_CLIENT = os.environ.get("TPLINK_ROUTER_CLIENT")
TPLINK_ROUTER_TIMEOUT = env_int("TPLINK_ROUTER_TIMEOUT", DEFAULT_TIMEOUT)
TPLINK_ROUTER_VERIFY_SSL = env_bool("TPLINK_ROUTER_VERIFY_SSL")
TPLINK_TRY_USERS = os.environ.get("TPLINK_TRY_USERS")

METRICS_PORT = env_int("METRICS_PORT", 9105)
SCRAPE_INTERVAL = env_int("SCRAPE_INTERVAL", 60)
STALE_AFTER_FAILURES = env_int("STALE_AFTER_FAILURES", 3)
RECONNECT_AFTER_POLL_FAILURES = env_int("RECONNECT_AFTER_POLL_FAILURES", 3)
RECONNECT_BACKOFF_SECONDS = env_int("RECONNECT_BACKOFF_SECONDS", 5)
RECONNECT_BACKOFF_MAX_SECONDS = env_int("RECONNECT_BACKOFF_MAX_SECONDS", 120)
EXIT_AFTER_SECONDS_WITHOUT_POLL_SUCCESS = env_int("EXIT_AFTER_SECONDS_WITHOUT_POLL_SUCCESS", 0)
EXIT_AFTER_CONSECUTIVE_INIT_FAILURES = env_int("EXIT_AFTER_CONSECUTIVE_INIT_FAILURES", 0)


def device_name() -> str:
    explicit = os.environ.get("TPLINK_ROUTER_NAME")
    if explicit:
        return explicit
    parsed = urlparse(TPLINK_ROUTER_HOST)
    if parsed.hostname:
        return parsed.hostname
    return TPLINK_ROUTER_HOST


def get_password() -> str | None:
    return TPLINK_ROUTER_PASSWORD
