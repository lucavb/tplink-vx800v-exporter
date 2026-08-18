"""Logging helpers and sensitive-data redaction."""

from __future__ import annotations

import logging
import re
import sys
import time
import traceback
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from re import search
from typing import Any

SENSITIVE_PATTERNS = (
    (re.compile(r"(Passwd|password|passwd|UserName|username)=([^&\s]+)", re.I), r"\1=<redacted>"),
    (re.compile(r'"(?:password|passwd|Passwd)"\s*:\s*"[^"]*"', re.I), '"password":"<redacted>"'),
    (re.compile(r"(sign|data|token|TokenID)=([A-Za-z0-9%+/=]{8,})"), r"\1=<redacted>"),
    (re.compile(r'var token="([^"]+)";'), 'var token="<redacted>";'),
    (re.compile(r"(JSESSIONID)=[^;\s]+", re.I), r"\1=<redacted>"),
)


class SensitiveLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.getMessage()))
        record.args = ()
        return True


def redact(text: str) -> str:
    out = text
    for pattern, repl in SENSITIVE_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def parse_js_ret(response_text: str) -> tuple[int | None, str]:
    result = search(r"\$\.ret=([^;]+);", response_text)
    if result is None:
        return None, redact(response_text[:500])
    raw = result.group(1).strip().strip('"')
    if raw.isnumeric():
        return int(raw), redact(response_text[:500])
    return None, redact(response_text[:500])


def read_http_body(response) -> str:
    raw = b""
    try:
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                raw += chunk
    except Exception:
        pass
    return raw.decode("utf-8", errors="replace")


class ProbeLog:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def info(self, message: str) -> None:
        if self.enabled:
            print(f"[exporter] {message}", file=sys.stderr)

    def step_start(self, name: str) -> float:
        self.info(f"START {name}")
        return time.monotonic()

    def step_end(self, name: str, started: float, detail: str = "") -> None:
        elapsed = time.monotonic() - started
        suffix = f" ({detail})" if detail else ""
        self.info(f"OK   {name} in {elapsed:.2f}s{suffix}")

    def step_fail(self, name: str, started: float, exc: BaseException) -> None:
        elapsed = time.monotonic() - started
        self.info(f"FAIL {name} after {elapsed:.2f}s: {redact(str(exc))}")
        if self.enabled:
            tb = traceback.format_exc()
            if tb.strip() != "NoneType: None\n":
                print(redact(tb), file=sys.stderr)


def run_step(log: ProbeLog, name: str, fn: Callable[[], Any]) -> Any:
    started = log.step_start(name)
    try:
        result = fn()
    except Exception as exc:
        log.step_fail(name, started, exc)
        raise
    log.step_end(name, started)
    return result


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    return value


def configure_tplink_logging(debug: bool) -> None:
    if not debug:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(SensitiveLogFilter())
    logging.basicConfig(
        level=logging.DEBUG,
        format="[tplinkrouterc6u] %(levelname)s %(message)s",
        handlers=[handler],
        force=True,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
