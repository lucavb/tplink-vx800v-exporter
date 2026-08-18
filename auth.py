"""Authentication and session management for VX800v routers."""

from __future__ import annotations

import logging
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from hashlib import md5
from http.cookiejar import CookieJar
from typing import Any

from logging_utils import ProbeLog, read_http_body, redact, run_step, to_jsonable
from parsers import collect_cgi_metrics, collect_status_overview, collect_wifi_metrics
from router import (
    Vx800vEXClientGCM,
    host_entry_to_client_dict,
    install_vx_chunked_request,
    merge_connected_clients,
    vx_clear_busy,
    vx_fetch_host_entries,
)

DEFAULT_HOST = "https://192.168.1.1"
DEFAULT_TIMEOUT = 60

VX_AGINET_CLIENTS = (
    "TPLinkEXClientGCM",
    "TPLinkEXClient",
    "TplinkVR1200vRouter",
)


def is_vx_aginet_model(model: str | None) -> bool:
    return bool(model and model.upper().startswith("VX"))


def resolve_username(model: str | None, explicit_user: str | None) -> str:
    if os.environ.get("TPLINK_ROUTER_USER"):
        return os.environ["TPLINK_ROUTER_USER"]
    if explicit_user:
        return explicit_user
    if is_vx_aginet_model(model):
        return "user"
    return "admin"


def parse_login_page_flags(html: str) -> dict[str, str]:
    flags: dict[str, str] = {}
    for key in (
        "adminType",
        "INCLUDE_LOGIN_USERNAME",
        "INCLUDE_USER_RESTRICTION",
        "INCLUDE_LOGIN_GDPR_ENCRYPT",
    ):
        matches = re.findall(rf"var {key}\s*=\s*([^;]+);", html)
        if matches:
            flags[key] = matches[-1].strip().strip('"')
    return flags


def username_candidates(primary: str | None, login_flags: dict[str, str] | None) -> list[str]:
    flags = login_flags or {}
    candidates: list[str] = []
    if primary:
        candidates.append(primary)
    if flags.get("INCLUDE_LOGIN_USERNAME") == "0" and flags.get("INCLUDE_USER_RESTRICTION") == "1":
        forced = "admin" if flags.get("adminType") == "admin" else "user"
        if forced not in candidates:
            candidates.append(forced)
    for candidate in ("user", "admin", ""):
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def build_opener(verify_ssl: bool) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    jar = CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )


def welcome_handshake(opener: urllib.request.OpenerDirector, host: str, timeout: int) -> str | None:
    http_host = host.replace("https://", "http://").replace("http://", "http://")
    if not http_host.startswith("http://"):
        http_host = "http://" + http_host.removeprefix("https://")
    req = urllib.request.Request(
        f"{http_host}/cgi/welcome",
        method="POST",
        headers={"User-Agent": "tplink-vx800v-probe/1.0"},
    )
    with opener.open(req, timeout=timeout) as resp:
        return resp.headers.get("Location")


def post_cgi(
    opener: urllib.request.OpenerDirector,
    host: str,
    path: str,
    timeout: int,
    payload: bytes | None = b"{}",
) -> tuple[int, str]:
    req = urllib.request.Request(
        f"{host.rstrip('/')}{path}",
        data=payload,
        method="POST",
        headers={
            "User-Agent": "tplink-vx800v-exporter/1.0",
            "Referer": f"{host.rstrip('/')}/",
            "Content-Type": "application/json; charset=UTF-8",
        },
    )
    with opener.open(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def parse_js_vars(body: str) -> dict[str, str]:
    vars_out: dict[str, str] = {}
    for key, value in re.findall(r'var\s+(\w+)="([^"]*)";', body):
        vars_out[key] = value
    for key, value in re.findall(r"var\s+(\w+)=([^;]+);", body):
        if key not in vars_out:
            vars_out[key] = value.strip().strip('"')
    return vars_out


def probe_unauthenticated(
    host: str, verify_ssl: bool, timeout: int, log: ProbeLog
) -> dict[str, Any]:
    opener = build_opener(verify_ssl)
    result: dict[str, Any] = {"host": host, "reachable": False, "model": None, "cgis": {}}

    try:
        location = run_step(
            log, "welcome_handshake", lambda: welcome_handshake(opener, host, timeout)
        )
        result["welcome_redirect"] = location
        result["reachable"] = True
    except Exception as exc:  # noqa: BLE001 - diagnostic script
        result["error"] = f"welcome handshake failed: {exc}"
        return result

    headers = {
        "User-Agent": "tplink-vx800v-exporter/1.0",
        "Referer": f"{host.rstrip('/')}/",
    }
    try:

        def fetch_login_page() -> str:
            with opener.open(
                urllib.request.Request(f"{host.rstrip('/')}/", headers=headers),
                timeout=timeout,
            ) as resp:
                return resp.read().decode("utf-8", errors="replace")

        html = run_step(log, "fetch_login_page", fetch_login_page)
        for key in ("modelName", "modelDesc"):
            match = re.search(rf'var {key}="([^"]+)"', html)
            if match:
                result[key] = match.group(1)
        result["model"] = result.get("modelName")
        result["login_page_bytes"] = len(html.encode("utf-8"))
        result["login_flags"] = parse_login_page_flags(html)
    except Exception as exc:  # noqa: BLE001
        result["login_page_error"] = str(exc)

    for path in ("/cgi/getBusy", "/cgi/getGDPRParm", "/cgi/checkCloudConn", "/cgi/getEwebUrl"):
        try:
            status, body = run_step(
                log,
                f"unauth{path}",
                lambda p=path: post_cgi(opener, host, p, timeout),
            )
            result["cgis"][path] = {
                "status": status,
                "vars": parse_js_vars(body),
                "raw": redact(body.strip()),
            }
        except urllib.error.HTTPError as exc:
            result["cgis"][path] = {
                "status": exc.code,
                "error": redact(exc.read().decode("utf-8", errors="replace")[:200]),
            }
        except Exception as exc:  # noqa: BLE001
            result["cgis"][path] = {"error": str(exc)}

    return result


def try_logout(host: str, verify_ssl: bool, timeout: int, log: ProbeLog) -> dict[str, Any]:
    opener = build_opener(verify_ssl)
    welcome_handshake(opener, host, timeout)
    headers = {
        "User-Agent": "tplink-vx800v-exporter/1.0",
        "Referer": f"{host.rstrip('/')}/",
        "Content-Type": "application/json; charset=UTF-8",
    }
    result: dict[str, Any] = {"ok": False}
    try:
        req = urllib.request.Request(
            f"{host.rstrip('/')}/cgi/logout",
            data=b"{}",
            method="POST",
            headers=headers,
        )
        with opener.open(req, timeout=timeout) as resp:
            result["status"] = resp.status
            result["body"] = redact(resp.read(300).decode("utf-8", errors="replace"))
            result["ok"] = True
        _, busy_body = post_cgi(opener, host, "/cgi/getBusy", timeout)
        result["busy_after"] = parse_js_vars(busy_body)
        log.info(f"logout complete; busy={result.get('busy_after')}")
    except Exception as exc:  # noqa: BLE001
        result["error"] = redact(str(exc))
        log.info(f"logout failed: {result['error']}")
    return result


def warmup_vx_session(client, host: str, log: ProbeLog) -> None:
    started = log.step_start("authorize.warmup_get_root")
    try:
        response = client.req.get(
            f"{host.rstrip('/')}/",
            headers={
                "User-Agent": client.HEADERS["User-Agent"],
                "Referer": f"{host.rstrip('/')}/",
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
            timeout=client.timeout,
            verify=client._verify_ssl,
            stream=True,
        )
        read_http_body(response)
        log.step_end("authorize.warmup_get_root", started, f"http={response.status_code}")
    except Exception as exc:  # noqa: BLE001
        log.step_fail("authorize.warmup_get_root", started, exc)
        raise


def select_client(
    host: str,
    password: str,
    username: str,
    verify_ssl: bool,
    timeout: int,
    log: ProbeLog,
    model: str | None = None,
    forced_client: str | None = None,
    login_flags: dict[str, str] | None = None,
    try_users: list[str] | None = None,
):
    from tplinkrouterc6u.common.exception import ClientException
    from tplinkrouterc6u.provider import TplinkRouterProvider

    logger = logging.getLogger("tplink-vx800v-exporter")
    if not log.enabled:
        logger.disabled = True
    clients = TplinkRouterProvider.get_clients()
    tried: list[dict[str, Any]] = []

    if is_vx_aginet_model(model):
        users = try_users or username_candidates(username, login_flags)
        log.info(
            "VX Aginet model detected (%s); native GCM login with usernames: %s"
            % (model, ", ".join(repr(u) for u in users))
        )
        last_error: str | None = None
        for candidate in users:
            started = log.step_start(f"client.authorize:Vx800vEXClientGCM:{candidate!r}")
            entry: dict[str, Any] = {"client": "Vx800vEXClientGCM", "username": candidate}
            router = Vx800vEXClientGCM(host, password, candidate, logger, verify_ssl, timeout)
            router._inner.HEADERS.update(
                {
                    "Accept": "text/plain, */*; q=0.01",
                    "Connection": "keep-alive",
                    "Content-Type": "text/plain",
                    "Origin": host.rstrip("/"),
                    "Referer": f"{host.rstrip('/')}/",
                    "X-Requested-With": "XMLHttpRequest",
                }
            )
            router._inner._hash = md5(f"{candidate}{password}".encode()).hexdigest()
            try:
                warmup_vx_session(router._inner, host, log)
                authorize_client(router, log)
                entry["authorized"] = True
                entry["login_preview"] = getattr(router, "_login_preview", None)
                log.step_end(
                    f"client.authorize:Vx800vEXClientGCM:{candidate!r}", started, "authorized"
                )
                tried.append(entry)
                log.info(f"selected client: Vx800vEXClientGCM username={candidate!r}")
                return router, tried
            except Exception as exc:  # noqa: BLE001
                entry["authorized"] = False
                entry["error"] = redact(str(exc))
                entry["login_preview"] = getattr(router, "_login_preview", None)
                log.step_fail(f"client.authorize:Vx800vEXClientGCM:{candidate!r}", started, exc)
                tried.append(entry)
                last_error = entry["error"]
                router._inner._token = None
        raise ClientException(
            "No VX Aginet username could authorize. "
            f"Tried: {', '.join(repr(u) for u in users)}. Last error: {last_error or 'unknown'}. "
            "Set TPLINK_ROUTER_USER to the same username you use in the web UI."
        )

    if forced_client:
        order = [forced_client]
    else:
        order = list(clients.keys())

    last_error = None
    for client_name in order:
        client_cls = clients.get(client_name)
        if client_cls is None:
            tried.append({"client": client_name, "error": "unknown client class"})
            continue

        router = client_cls(host, password, username, logger, verify_ssl, timeout)
        started = log.step_start(f"client.authorize:{client_name}")
        entry: dict[str, Any] = {"client": client_name, "username": username}

        if is_vx_aginet_model(model):
            try:
                authorize_client(router, log)
                entry["authorized"] = True
                log.step_end(f"client.authorize:{client_name}", started, "authorized")
                tried.append(entry)
                log.info(f"selected client: {client_name}")
                return router, tried
            except Exception as exc:  # noqa: BLE001
                entry["authorized"] = False
                entry["error"] = redact(str(exc))
                log.step_fail(f"client.authorize:{client_name}", started, exc)
                tried.append(entry)
                last_error = entry["error"]
                router._token = None  # type: ignore[attr-defined]
                continue

        entry["supports"] = False
        try:
            entry["supports"] = router.supports()
            log.step_end(f"client.supports:{client_name}", started, f"supports={entry['supports']}")
        except Exception as exc:  # noqa: BLE001
            entry["error"] = redact(str(exc))
            log.step_fail(f"client.supports:{client_name}", started, exc)
            last_error = entry["error"]
        tried.append(entry)
        if entry.get("supports"):
            log.info(f"selected client: {client_name}")
            return router, tried

    log.info("no client matched supports(); falling back to provider.get_client()")
    try:
        selected = TplinkRouterProvider.get_client(
            host,
            password,
            username=username,
            logger=logger,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        tried.append({"client": selected.__class__.__name__, "supports": "provider_fallback"})
        return selected, tried
    except ClientException as exc:
        tried.append({"client": None, "error": redact(str(exc))})
        raise


def authorize_client(client, log: ProbeLog) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    router = client._inner if hasattr(client, "_inner") else client

    def record(
        name: str, started: float, ok: bool, detail: str = "", error: str | None = None
    ) -> None:
        steps.append(
            {
                "step": name,
                "seconds": round(time.monotonic() - started, 2),
                "ok": ok,
                "detail": detail,
                "error": error,
            }
        )

    router._token = None

    started = log.step_start("authorize._req_rsa_key")
    try:
        nn, ee, seq = router._req_rsa_key()
        router._nn, router._ee, router._seq = nn, ee, seq
        log.step_end(
            "authorize._req_rsa_key", started, f"seq={seq} nn_len={len(nn)} ee_len={len(ee)}"
        )
        record("authorize._req_rsa_key", started, True, f"seq={seq}")
    except Exception as exc:
        log.step_fail("authorize._req_rsa_key", started, exc)
        record("authorize._req_rsa_key", started, False, error=redact(str(exc)))
        raise

    started = log.step_start("authorize._req_login")
    try:
        if hasattr(client, "_req_login"):
            client._req_login()
        else:
            router._req_login()
        log.step_end("authorize._req_login", started)
        record("authorize._req_login", started, True)
    except Exception as exc:
        log.step_fail("authorize._req_login", started, exc)
        record("authorize._req_login", started, False, error=redact(str(exc)))
        raise

    started = log.step_start("authorize._req_token")
    try:
        token = router._req_token()
        router._token = token
        router._authorized_at = __import__("datetime").datetime.now()
        log.step_end("authorize._req_token", started, f"token_len={len(token)}")
        record("authorize._req_token", started, True, f"token_len={len(token)}")
    except Exception as exc:
        log.step_fail("authorize._req_token", started, exc)
        record("authorize._req_token", started, False, error=redact(str(exc)))
        raise

    return steps


def connect_router(
    host: str,
    password: str,
    username: str,
    verify_ssl: bool,
    timeout: int,
    log: ProbeLog,
    *,
    model: str | None = None,
    forced_client: str | None = None,
    logout_first: bool = False,
    login_flags: dict[str, str] | None = None,
    try_users: list[str] | None = None,
) -> tuple[Any, str]:
    """Authenticate and return (client, client_class_name)."""
    if logout_first:
        run_step(log, "logout_before_auth", lambda: try_logout(host, verify_ssl, timeout, log))

    client, selection = run_step(
        log,
        "select_client",
        lambda: select_client(
            host,
            password,
            username,
            verify_ssl,
            timeout,
            log,
            model=model,
            forced_client=forced_client,
            login_flags=login_flags,
            try_users=try_users,
        ),
    )
    already_authorized = any(entry.get("authorized") for entry in selection)
    if not already_authorized:
        run_step(log, "authorize", lambda: authorize_client(client, log))

    if hasattr(client, "_inner"):
        install_vx_chunked_request(client._inner)

    client_name = (
        client._inner.__class__.__name__ if hasattr(client, "_inner") else client.__class__.__name__
    )
    return client, client_name


def collect_router_metrics(client: Any, log: ProbeLog) -> dict[str, Any]:
    """Collect all metrics from an authenticated session (no logout)."""
    router = client._inner if hasattr(client, "_inner") else client
    metrics_client = client if hasattr(client, "_inner") else router
    metrics: dict[str, Any] = {}

    try:
        metrics["get_firmware"] = to_jsonable(metrics_client.get_firmware())
    except Exception:
        raise

    # Generic status methods are intentionally omitted because they repeat LAN,
    # WAN, host, Wi-Fi, and CPU/memory requests already made in this poll.
    metrics["overview"] = collect_status_overview(router, log)
    metrics["cgi"] = collect_cgi_metrics(client, log)

    vx_clear_busy(router, is_user_active=True)
    clients: list[dict[str, Any]] = []
    try:
        host_entries = vx_fetch_host_entries(router)
        for entry in host_entries:
            client_dict = host_entry_to_client_dict(router, entry)
            if client_dict:
                clients.append(client_dict)
        metrics["clients"] = clients

        wifi_metrics = collect_wifi_metrics(router, log, host_entries)
        wifi_clients = wifi_metrics.get("clients") or []
        metrics["wifi"] = wifi_metrics
        metrics["wifi_clients"] = wifi_clients
        metrics["connected_clients"] = merge_connected_clients(clients, wifi_clients)
    finally:
        vx_clear_busy(router, is_user_active=None)

    return metrics
