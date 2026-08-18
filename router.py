"""TP-Link VX800v router client and OID helpers."""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any

from logging_utils import parse_js_ret, read_http_body, redact

logger = logging.getLogger(__name__)


def _act_data_summary(data: Any) -> str:
    """Describe an ACT response without logging client or network values."""
    if data is None:
        return "none"
    if isinstance(data, dict):
        return f"dict keys={sorted(str(key) for key in data)}"
    if isinstance(data, list):
        entry_types = sorted({type(entry).__name__ for entry in data})
        return f"list count={len(data)} entry_types={entry_types}"
    return type(data).__name__


def _act_response_summary(response: Any) -> str:
    """Describe a decrypted ACT response without logging payload values."""
    if not isinstance(response, str):
        return type(response).__name__
    try:
        payload = json.loads(response)
    except (TypeError, ValueError):
        ret_code, _ = parse_js_ret(response)
        return f"text length={len(response)} ret={ret_code}"
    if isinstance(payload, dict):
        result = f"json length={len(response)} keys={sorted(str(key) for key in payload)}"
        if "success" in payload or "errorcode" in payload:
            result += f" success={payload.get('success')!r} errorcode={payload.get('errorcode')!r}"
        return result
    return f"json length={len(response)} type={type(payload).__name__}"


def build_vx_login_payload(username_plain: str, password_plain: str, action: str = "1") -> str:
    # VX800v firmware rejects JSON numeric Action (1); it must be the string "1"
    # like tplinkrouterc6u and the web UI send. A numeric value yields garbled HTTP.
    payload = {
        "data": {
            "UserName": base64.b64encode(username_plain.encode("utf-8")).decode("utf-8"),
            "Passwd": base64.b64encode(password_plain.encode("utf-8")).decode("utf-8"),
            "Action": action,
            "stack": "0,0,0,0,0,0",
            "pstack": "0,0,0,0,0,0",
        },
        "operation": "cgi",
        "oid": "/cgi/login",
    }
    return json.dumps(payload, separators=(",", ":"))


def wifi_enable_value(entry: dict[str, Any] | None, *, guest: bool = False) -> bool | None:
    if not entry:
        return None
    keys = (
        ("guestEnable", "guest_enable", "X_TP_GuestEnable")
        if guest
        else (
            "primaryEnable",
            "enable",
            "radioEnable",
            "bEnable",
            "X_TP_Enable",
            "X_TP_PrimaryEnable",
        )
    )
    for key in keys:
        raw = entry.get(key)
        if raw is None or str(raw).strip() == "":
            continue
        try:
            return bool(int(raw))
        except (TypeError, ValueError):
            continue
    return None


def apply_wifi_status(status: Any, wifi_values: Any) -> None:
    if not wifi_values:
        return
    if isinstance(wifi_values, list):
        if wifi_values:
            status.wifi_2g_enable = wifi_enable_value(wifi_values[0])
            status.guest_2g_enable = wifi_enable_value(wifi_values[0], guest=True)
        if len(wifi_values) > 1:
            status.wifi_5g_enable = wifi_enable_value(wifi_values[1])
            status.guest_5g_enable = wifi_enable_value(wifi_values[1], guest=True)
    elif isinstance(wifi_values, dict):
        status.wifi_2g_enable = wifi_enable_value(wifi_values)
        status.guest_2g_enable = wifi_enable_value(wifi_values, guest=True)


def vx_chunked_request(
    inner: Any,
    url: str,
    method: str = "POST",
    data_str: str | None = None,
    encrypt: bool = False,
    is_login: bool = False,
) -> tuple[int, str]:
    """Chunked-safe HTTP request for VX800v (tplinkrouterc6u uses r.text and can truncate)."""
    headers = dict(inner.HEADERS)
    headers["Referer"] = f"{inner.host}/"
    headers["Connection"] = "keep-alive"
    if inner._token is not None:
        headers["TokenID"] = inner._token

    if encrypt:
        if data_str is None:
            raise ValueError("data_str is required when encrypt=True")
        sign, data, tag = inner._prepare_data(data_str, is_login)
        payload = f"sign={sign}\r\ndata={data}\r\ntag={tag}\r\n"
    else:
        payload = data_str

    retry = 0
    response = None
    body = ""
    while retry < inner.REQUEST_RETRIES:
        if method == "POST":
            response = inner.req.post(
                url,
                data=payload,
                headers=headers,
                timeout=inner.timeout,
                verify=inner._verify_ssl,
                stream=True,
            )
        elif method == "GET":
            response = inner.req.get(
                url,
                data=payload,
                headers=headers,
                timeout=inner.timeout,
                verify=inner._verify_ssl,
                stream=True,
            )
        else:
            raise RuntimeError(f"unsupported method {method}")

        body = read_http_body(response)
        if (
            response.status_code not in [500, 406]
            and "<title>500 Internal Server Error</title>" not in body
            and "<title>406 Not Acceptable</title>" not in body
        ):
            if encrypt and response.status_code == 200 and body:
                return response.status_code, inner._encryption.aes_decrypt(body)
            return response.status_code, body

        retry += 1
        time.sleep(0.1)

    assert response is not None
    if encrypt and response.status_code == 200 and body:
        return response.status_code, inner._encryption.aes_decrypt(body)
    return response.status_code, body


def install_vx_chunked_request(inner: Any) -> None:
    """Patch tplinkrouterc6u to read full encrypted cgi_gdpr responses."""
    inner._request = lambda url, method="POST", data_str=None, encrypt=False, is_login=False: (
        vx_chunked_request(inner, url, method, data_str, encrypt, is_login)
    )


def vx_req_act_values(inner: Any, acts: list[Any]) -> list[Any]:
    """Run ACTs; return the values list (empty when the router omits data)."""
    try:
        response, values = inner.req_act(acts)
    except Exception as exc:  # noqa: BLE001 - collect partial metrics
        logger.debug(
            "ACT request failed oid=%s op=%s: %s",
            getattr(acts[0], "oid", "unknown") if acts else "none",
            getattr(acts[0], "type", "unknown") if acts else "none",
            redact(str(exc)),
        )
        return []
    if not values:
        logger.debug(
            "ACT response omitted data oid=%s op=%s: %s",
            getattr(acts[0], "oid", "unknown") if acts else "none",
            getattr(acts[0], "type", "unknown") if acts else "none",
            _act_response_summary(response),
        )
        return []
    if isinstance(values, list):
        return values
    return [values]


def vx_req_act_data(inner: Any, act: Any) -> Any | None:
    """Run one ACT; return its data payload or None when the router omits data."""
    values = vx_req_act_values(inner, [act])
    if not values:
        return None
    return values[0]


def vx_ui_request(
    inner: Any,
    operation: str,
    oid: str,
    attrs: list[str] | None = None,
    *,
    stack: str = "0,0,0,0,0,0",
    pstack: str = "0,0,0,0,0,0",
    is_user_active: bool | None = True,
    ajax_async: bool | None = None,
) -> Any | None:
    """Run a browser-equivalent request required by VX800v UI data models."""
    payload = {
        "data": {
            "stack": stack,
            "pstack": pstack,
            **{attr: "" for attr in (attrs or [])},
        },
        "operation": operation,
        "oid": oid,
    }
    if is_user_active is not None:
        payload["isuseractive"] = is_user_active
    if ajax_async is not None:
        payload["ajax"] = {"async": ajax_async}
    payload_text = json.dumps(payload, separators=(",", ":")) + "\r\n"
    sign, encrypted_data, tag = inner._prepare_data(payload_text, False)
    request_body = f"sign={sign}\r\ndata={encrypted_data}\r\ntag={tag}\r\n"
    headers = {
        **inner.HEADERS,
        "Accept": "text/plain, */*; q=0.01",
        "Connection": "keep-alive",
        "Content-Type": "text/plain",
        "Origin": inner.host,
        "Referer": f"{inner.host}/",
        "X-Requested-With": "XMLHttpRequest",
    }
    if inner._token is not None:
        headers["TokenID"] = inner._token
    response = inner.req.post(
        f"{inner.host.rstrip('/')}/cgi_gdpr?9",
        data=request_body,
        headers=headers,
        timeout=inner.timeout,
        verify=inner._verify_ssl,
        stream=True,
    )
    encrypted_body = read_http_body(response)
    if response.status_code != 200 or not encrypted_body:
        return None
    body = inner._encryption.aes_decrypt(encrypted_body)
    try:
        result = json.loads(body)
    except ValueError:
        return None
    if not isinstance(result, dict) or not result.get("success"):
        return None
    return result.get("data")


def vx_clear_busy(inner: Any, *, is_user_active: bool | None) -> None:
    """Release the UI busy lock around dynamic-list collection."""
    vx_ui_request(
        inner,
        inner.ActItem.CGI,
        "/cgi/clearBusy",
        is_user_active=is_user_active,
        ajax_async=False,
    )


def vx_fetch_act_variants(
    inner: Any,
    oid: str,
    attrs: list[str] | None = None,
    *,
    operations: tuple[str, ...] = ("GO", "GET", "GL"),
    stacks: tuple[str, ...] = ("0,0,0,0,0,0",),
) -> Any | None:
    ActItem = inner.ActItem
    attr_list = attrs if attrs is not None else []
    for stack in stacks:
        for op_name in operations:
            data = vx_req_act_data(
                inner, ActItem(getattr(ActItem, op_name), oid, stack=stack, attrs=attr_list)
            )
            if data:
                return data
    return None


def flatten_act_entries(inner: Any, data: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for item in inner._to_list(data):
        if isinstance(item, dict):
            entries.append(item)
        elif isinstance(item, list):
            for sub in item:
                if isinstance(sub, dict):
                    entries.append(sub)
    return entries


def first_field(item: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        raw = item.get(key)
        if raw is None:
            continue
        text = str(raw).strip()
        if text and text not in {"0", "0.0.0.0", "::"}:
            return text
    return None


WAN_IP_KEYS = ("connIPv4Address", "externalIPAddress", "IPAddress", "ipAddress")
WAN_GW_KEYS = ("connIPv4Gateway", "defaultGateway", "gateway")
WAN_MAC_KEYS = ("MACAddr", "MACAddress", "X_TP_MACAddress")
WAN_ENABLE_KEYS = ("enable", "Enable", "connStatus", "connectStatus")


def vx_wan_entries(inner: Any) -> list[dict[str, Any]]:
    attrs = [
        "enable",
        "MACAddr",
        "connIPv4Address",
        "connIPv4Gateway",
        "name",
        "connIPv4SubnetMask",
        "connIPv4DnsServer",
        "X_TP_IPv6Enabled",
        "X_TP_IPv6ConnStatus",
        "X_TP_ExternalIPv6Address",
        "X_TP_DefaultIPv6Gateway",
        "X_TP_IPv6DNSServers",
    ]
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for stack in ("0,0,0,0,0,0", "1,0,0,0,0,0", "2,0,0,0,0,0"):
        data = vx_fetch_act_variants(inner, "DEV2_ADT_WAN", attrs=attrs, stacks=(stack,))
        for item in flatten_act_entries(inner, data):
            marker = (
                first_field(item, WAN_IP_KEYS)
                or first_field(item, WAN_MAC_KEYS)
                or str(sorted(item.items()))
            )
            if marker in seen:
                continue
            seen.add(marker)
            entries.append(item)
    if not entries:
        data = vx_fetch_act_variants(
            inner, "DEV2_ADT_WAN", attrs=[], stacks=("0,0,0,0,0,0", "1,0,0,0,0,0")
        )
        entries.extend(flatten_act_entries(inner, data))
    return entries


def wan_entry_connected(item: dict[str, Any]) -> bool:
    ip = first_field(item, WAN_IP_KEYS)
    if ip:
        return True
    for key in WAN_ENABLE_KEYS:
        raw = item.get(key)
        if raw is None:
            continue
        try:
            if int(raw) != 0:
                return True
        except (TypeError, ValueError):
            if str(raw).strip().lower() in {"connected", "up", "true"}:
                return True
    return False


def vx_cpu_mem(inner: Any) -> tuple[float | None, float | None]:
    """Legacy OID path; VX800v firmware does not populate DEV2_MEM_STATUS / DEV2_PROC_STATUS."""
    mem = vx_fetch_act_variants(inner, "DEV2_MEM_STATUS", attrs=["total", "free"])
    cpu = vx_fetch_act_variants(inner, "DEV2_PROC_STATUS", attrs=["CPUUsage"])
    if not isinstance(mem, dict):
        mem = vx_fetch_act_variants(inner, "DEV2_MEM_STATUS", attrs=[])
    if not isinstance(cpu, dict):
        cpu = vx_fetch_act_variants(inner, "DEV2_PROC_STATUS", attrs=[])
    mem_usage = None
    if isinstance(mem, dict) and mem.get("total"):
        try:
            total = int(mem["total"])
            free = int(mem.get("free", 0))
            if total > 0:
                mem_usage = (total - free) / total
        except (TypeError, ValueError):
            pass
    cpu_usage = None
    if isinstance(cpu, dict) and cpu.get("CPUUsage") is not None:
        try:
            cpu_usage = int(cpu["CPUUsage"]) / 100
        except (TypeError, ValueError):
            pass
    return cpu_usage, mem_usage


def fetch_authenticated_get(router: Any, path: str) -> tuple[int, str]:
    """GET a router CGI endpoint using the authorized requests session."""
    headers = dict(router.HEADERS)
    headers["Referer"] = f"{router.host}/"
    headers["Connection"] = "close"
    if router._token is not None:
        headers["TokenID"] = router._token
    response = router.req.get(
        f"{router.host.rstrip('/')}{path}",
        headers=headers,
        timeout=router.timeout,
        verify=router._verify_ssl,
        stream=True,
    )
    return response.status_code, read_http_body(response)


def fetch_show_dsl_stats(router: Any) -> tuple[int, str]:
    """DSL-Info page: GET /cgi/showDslStats (same as $.dm.cgi in dslShowDslInfo.htm)."""
    status, body = fetch_authenticated_get(router, "/cgi/showDslStats")
    if status == 200 and "Statistics_buf" in body:
        return status, body

    ActItem = router.ActItem
    try:
        payload = vx_req_act_data(router, ActItem(ActItem.CGI, "/cgi/showDslStats"))
    except Exception:  # noqa: BLE001
        payload = None

    if isinstance(payload, str) and "Statistics_buf" in payload:
        return 200, payload
    if isinstance(payload, dict):
        for key in ("data", "result", "response"):
            text = payload.get(key)
            if isinstance(text, str) and "Statistics_buf" in text:
                return 200, text

    return status, body


def parse_js_int_var(body: str, var_name: str) -> int | None:
    match = re.search(rf"var\s+{re.escape(var_name)}\s*=\s*(-?\d+)\s*;", body)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def parse_cpu_mem_cgi(router: Any) -> tuple[float | None, float | None]:
    """CPU and memory from /cgi/getCpuLoad and /cgi/getMemUsage (web UI dashboard path)."""
    cpu_usage = None
    mem_usage = None
    try:
        _, cpu_body = fetch_authenticated_get(router, "/cgi/getCpuLoad?update")
        cpu_pct = parse_js_int_var(cpu_body, "newCpuLoad")
        if cpu_pct is not None:
            cpu_usage = cpu_pct / 100.0
    except Exception:  # noqa: BLE001
        pass
    try:
        _, mem_body = fetch_authenticated_get(router, "/cgi/getMemUsage?update")
        mem_pct = parse_js_int_var(mem_body, "newMemUsage")
        if mem_pct is not None:
            mem_usage = mem_pct / 100.0
    except Exception:  # noqa: BLE001
        pass
    return cpu_usage, mem_usage


DSL_STATS_BUF_RE = re.compile(r'var\s+Statistics_buf="((?:[^"\\]|\\.)*)"\s*;', re.DOTALL)
DSL_RATE_RE = re.compile(r"(Upstream|Downstream) rate = (\d+) Kbps")
DSL_SNR_RE = re.compile(r"SNR \(dB\):\s*([\d.]+)\s+([\d.]+)")
DSL_ATTN_RE = re.compile(r"Attn\(dB\):\s*([\d.]+)\s+([\d.]+)")
DSL_PWR_RE = re.compile(r"Pwr\(dBm\):\s*([\d.]+)\s+([\d.]+)")
DSL_COUNTER_PAIR_RE = re.compile(r"(\w+):\s*(\d+)\s+(\d+)")
DSL_UPTIME_RE = re.compile(
    r"Total time\s*=\s*(\d+)\s+days?\s+(\d+)\s+hours?\s+(\d+)\s+min(?:\s+(\d+)\s+sec)?",
    re.I,
)


def _dsl_section(text: str, marker: str) -> str:
    start = text.rfind(marker)
    if start < 0:
        return ""
    rest = text[start + len(marker) :]
    for end_marker in (
        "Latest 15 minutes",
        "Previous 15 minutes",
        "Latest 1 day",
        "Previous 1 day",
    ):
        end = rest.find(end_marker)
        if end >= 0:
            rest = rest[:end]
    return rest


def parse_dsl_stats(body: str) -> dict[str, Any]:
    """Parse /cgi/showDslStats (xdslctl dump wrapped as Statistics_buf)."""
    ret_code, _ = parse_js_ret(body)
    match = DSL_STATS_BUF_RE.search(body)
    if not match:
        return {"ok": False, "ret": ret_code, "error": "Statistics_buf missing"}

    raw = match.group(1)
    text = raw.replace(",", "\n")
    result: dict[str, Any] = {
        "ok": (ret_code is None or ret_code == 0),
        "ret": ret_code,
    }

    status_match = re.search(r"Status:\s*(\S+)", text)
    if status_match:
        result["status"] = status_match.group(1)
        result["link_up"] = status_match.group(1).lower() == "showtime"
        result["ok"] = True

    mode_match = re.search(r"Mode:\s*([A-Za-z0-9./+\- ]+?)(?:\s*,|\s*$)", raw)
    if not mode_match:
        mode_match = re.search(r"Mode:\s*([A-Za-z0-9./+\- ]+)", text)
    if mode_match:
        result["mode"] = mode_match.group(1).strip()

    profile_match = re.search(r"Gfast Profile:\s*([^,\n]+)", raw)
    if profile_match:
        result["profile"] = profile_match.group(1).strip()

    rates: dict[str, int] = {}
    bearer_rates: dict[str, int] = {}
    max_rates: dict[str, int] = {}
    in_bearer = False
    for part in raw.split(","):
        part = part.strip()
        if part.startswith("Bearer:"):
            in_bearer = True
            continue
        rate_match = DSL_RATE_RE.search(part)
        if not rate_match:
            continue
        direction = "up" if rate_match.group(1) == "Upstream" else "down"
        kbps = int(rate_match.group(2))
        if in_bearer:
            bearer_rates[direction] = kbps
        else:
            max_rates[direction] = kbps
        rates[direction] = kbps
    if bearer_rates:
        result["sync_rate_kbps"] = bearer_rates
    elif rates:
        result["sync_rate_kbps"] = rates
    if max_rates:
        result["max_rate_kbps"] = max_rates

    snr_match = DSL_SNR_RE.search(text)
    if snr_match:
        result["snr_db"] = {"down": float(snr_match.group(1)), "up": float(snr_match.group(2))}
    attn_match = DSL_ATTN_RE.search(text)
    if attn_match:
        result["attenuation_db"] = {
            "down": float(attn_match.group(1)),
            "up": float(attn_match.group(2)),
        }
    pwr_match = DSL_PWR_RE.search(text)
    if pwr_match:
        result["power_dbm"] = {"down": float(pwr_match.group(1)), "up": float(pwr_match.group(2))}

    uptime_match = DSL_UPTIME_RE.search(text)
    if uptime_match:
        days, hours, minutes, seconds = uptime_match.groups()
        result["link_uptime_seconds"] = (
            int(days) * 86400 + int(hours) * 3600 + int(minutes) * 60 + int(seconds or 0)
        )

    since_link = _dsl_section(text, "Since Link time")
    if not since_link:
        since_link = _dsl_section(text, "Since Link")
    if since_link:
        counters: dict[str, dict[str, int]] = {}
        for name, down, up in DSL_COUNTER_PAIR_RE.findall(since_link):
            if name in {"CRC", "ES", "SES", "UAS", "LOS", "LOF", "LOM", "FEC", "Retr"}:
                counters[name.lower()] = {"down": int(down), "up": int(up)}
        if counters:
            result["counters_since_link"] = counters

    return result


def vx_fetch_host_entries(inner: Any) -> list[dict[str, Any]]:
    """Read host entries using the VX800v network-map request shape."""
    data = vx_ui_request(inner, inner.ActItem.GL, "DEV2_HOST_ENTRY")
    logger.debug("DEV2_HOST_ENTRY user-active response: %s", _act_data_summary(data))
    return _entries_from_act_data(inner, data)


def _entries_from_act_data(inner: Any, data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []
    return flatten_act_entries(inner, data)


def host_entry_to_client_dict(inner: Any, val: dict[str, Any]) -> dict[str, Any] | None:
    from tplinkrouterc6u.common.helper import get_ip, get_mac
    from tplinkrouterc6u.common.package_enum import Connection

    try:
        active = int(val.get("active", 0))
    except (TypeError, ValueError):
        active = 0
    if active == 0:
        return None

    conn = inner.CLIENT_TYPES.get(int(val.get("X_TP_LanConnType", -1)))
    conn_name = "unknown"
    if conn == Connection.WIRED:
        conn_name = "wired"
    elif conn is not None and conn.is_guest_wifi():
        conn_name = "guest_wifi"
    elif conn is not None and conn.is_host_wifi():
        conn_name = "wifi"

    lease_raw = val.get("leaseTimeRemaining")
    lease_seconds = None
    if lease_raw is not None:
        try:
            lease_val = int(lease_raw)
            if lease_val >= 0:
                lease_seconds = lease_val
        except (TypeError, ValueError):
            pass

    hostname = str(val.get("hostName") or "").strip() or "unknown"
    return {
        "mac": normalize_mac(str(get_mac(val.get("physAddress", "00:00:00:00:00:00")))),
        "ip": str(get_ip(val.get("IPAddress", "0.0.0.0"))),
        "hostname": hostname,
        "connection": conn_name,
        "address_source": str(val.get("addressSource") or "").strip() or None,
        "lease_seconds": lease_seconds,
        "active": bool(active),
    }


def normalize_mac(mac: str) -> str:
    """Canonical MAC for dedup/labels (uppercase, colon-separated)."""
    return str(mac or "").strip().upper().replace("-", ":")


def parse_router_int(raw: Any) -> int | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def hostnames_by_mac(host_entries: list[dict[str, Any]]) -> dict[str, str]:
    names: dict[str, str] = {}
    for entry in host_entries:
        mac = normalize_mac(str(entry.get("physAddress") or entry.get("MACAddress") or ""))
        hostname = str(entry.get("hostName") or "").strip()
        if mac and hostname:
            names[mac] = hostname
    return names


def vx_update_wifi_assoc(inner: Any) -> None:
    data = vx_ui_request(
        inner,
        inner.ActItem.OP,
        "ACT_WIFI_UPDATE_ALLASSOC",
        is_user_active=None,
    )
    logger.debug("ACT_WIFI_UPDATE_ALLASSOC response: %s", _act_data_summary(data))


def vx_fetch_wifi_clients(inner: Any, *, refresh: bool = True) -> list[dict[str, Any]]:
    """WLAN > Statistiken: refresh associations, then read DEV2_ADT_WIFI_CLIENT."""
    if refresh:
        vx_update_wifi_assoc(inner)

    data = vx_ui_request(
        inner,
        inner.ActItem.GL,
        "DEV2_ADT_WIFI_CLIENT",
    )
    logger.debug("DEV2_ADT_WIFI_CLIENT user-active response: %s", _act_data_summary(data))
    return _entries_from_act_data(inner, data)


def merge_connected_clients(
    lan_clients: list[dict[str, Any]],
    wifi_clients: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Unique connected devices by MAC; WLAN-only clients count toward the total."""
    by_mac: dict[str, dict[str, Any]] = {}
    for entry in lan_clients:
        mac = normalize_mac(str(entry.get("mac") or ""))
        if mac and mac != "00:00:00:00:00:00":
            by_mac[mac] = dict(entry)

    for entry in wifi_clients:
        mac = normalize_mac(str(entry.get("mac") or ""))
        if not mac or mac == "00:00:00:00:00:00":
            continue
        if mac in by_mac:
            existing = by_mac[mac]
            hostname = str(existing.get("hostname") or "").strip()
            if hostname in {"", "unknown"}:
                wifi_hostname = str(entry.get("hostname") or "").strip()
                if wifi_hostname:
                    existing["hostname"] = wifi_hostname
            if str(existing.get("connection") or "unknown") == "unknown":
                existing["connection"] = "wifi"
            continue

        by_mac[mac] = {
            "mac": mac,
            "ip": "0.0.0.0",
            "hostname": str(entry.get("hostname") or "").strip() or "unknown",
            "connection": "wifi",
            "address_source": None,
            "lease_seconds": None,
            "active": True,
        }

    return list(by_mac.values())


def wifi_client_to_dict(val: dict[str, Any], hostnames: dict[str, str]) -> dict[str, Any] | None:
    ap_type = str(val.get("APType") or "").strip()
    if ap_type == "Backhaul":
        return None

    mac = normalize_mac(str(val.get("MACAddress") or ""))
    if not mac or mac == "00:00:00:00:00:00":
        return None

    hostname = hostnames.get(mac, "").strip() or "unknown"
    band = str(val.get("band") or "unknown").strip()
    signal_dbm = parse_router_int(val.get("signalStrength"))

    return {
        "mac": mac,
        "hostname": hostname,
        "band": band,
        "ap_type": ap_type or "unknown",
        "mssid_index": parse_router_int(val.get("mssidIndex")),
        "signal_dbm": signal_dbm,
        "bytes_sent": parse_router_int(val.get("bytesSent")),
        "bytes_received": parse_router_int(val.get("bytesReceived")),
        "packets_sent": parse_router_int(val.get("packetsSent")),
        "packets_received": parse_router_int(val.get("packetsReceived")),
    }


WAN_SUMMARY_ATTRS = (
    "enable",
    "name",
    "customConnName",
    "connType",
    "accessMode",
    "MACAddr",
    "connStatusV4",
    "connStatusV6",
    "connIPv4Address",
    "connIPv4Gateway",
    "connIPv4DnsServer",
    "connIPv6Address",
    "connIPv6Gateway",
    "connIPv6DnsServer",
    "connIPv6Prefix",
    "connIPv6PreferredLifetime",
    "connIPv6ValidLifetime",
    "X_TP_Uptime",
    "X_TP_UptimeV6",
    "X_TP_DsliteAftrServer",
)

WIFI_RADIO_ATTRS = (
    "band",
    "standard",
    "bandwidth",
    "currentBandwidth",
    "autoChannel",
    "channel",
    "primaryEnable",
    "primarySSID",
    "primaryBSSID",
    "primaryModeEnabled",
    "primaryWPAWPA2EncryptionMode",
)

LAN_SUMMARY_ATTRS = (
    "MACAddress",
    "IPAddress",
    "IPSubnetMask",
    "DHCPv4Enable",
    "IPv6Address",
    "IPv6SitePrefix",
)

DSLITE_ATTRS = (
    "enable",
    "status",
    "endpointName",
    "endpointAddressInUse",
    "X_TP_ConnName",
)


def vx_fetch_oid_gl_list(
    inner: Any,
    oid: str,
    attrs: list[str] | None = None,
    *,
    stacks: tuple[str, ...] = ("0,0,0,0,0,0",),
) -> list[dict[str, Any]]:
    """GL list fetch; use explicit attrs when provided, otherwise empty filter like the web UI."""
    ActItem = inner.ActItem
    requested = list(attrs or [])
    for stack in stacks:
        attr_sets = (requested, []) if requested else ([],)
        for attr_set in attr_sets:
            data = vx_ui_request(
                inner,
                ActItem.GL,
                oid,
                list(attr_set),
                stack=stack,
                is_user_active=None,
            )
            entries = flatten_act_entries(inner, data)
            if entries:
                return entries
    return []


def vx_fetch_oid_get(
    inner: Any,
    oid: str,
    attrs: list[str] | None = None,
    *,
    stack: str = "0,0,0,0,0,0",
    stacks: tuple[str, ...] | None = None,
) -> dict[str, Any] | None:
    ActItem = inner.ActItem
    stack_list = stacks or (stack,)
    requested = list(attrs or [])
    for stack_name in stack_list:
        attr_sets = ([], requested) if requested else ([],)
        for attr_set in attr_sets:
            data = vx_ui_request(
                inner,
                ActItem.GET,
                oid,
                list(attr_set),
                stack=stack_name,
                is_user_active=None,
            )
            if isinstance(data, list) and data:
                data = data[0]
            if isinstance(data, dict) and data:
                return dict(data)

    return None


def wan_summary_dict(item: dict[str, Any]) -> dict[str, Any]:
    dns4 = [
        part.strip() for part in str(item.get("connIPv4DnsServer") or "").split(",") if part.strip()
    ]
    dns6 = [
        part.strip() for part in str(item.get("connIPv6DnsServer") or "").split(",") if part.strip()
    ]
    preferred = parse_router_int(item.get("connIPv6PreferredLifetime"))
    valid = parse_router_int(item.get("connIPv6ValidLifetime"))
    lifetime = None
    if preferred is not None and valid is not None:
        lifetime = f"{preferred}/{valid}s"
    transition = None
    if str(item.get("X_TP_DsliteAftrServer") or "").strip():
        transition = "DS-Lite"
    return {
        "name": str(item.get("customConnName") or item.get("name") or "").strip(),
        "conn_type": str(item.get("connType") or "").strip(),
        "access_mode": str(item.get("accessMode") or "").strip(),
        "mac": normalize_mac(str(item.get("MACAddr") or "")),
        "ipv4_status": str(item.get("connStatusV4") or "").strip(),
        "ipv6_status": str(item.get("connStatusV6") or "").strip(),
        "ipv4_address": str(item.get("connIPv4Address") or "").strip(),
        "ipv4_gateway": str(item.get("connIPv4Gateway") or "").strip(),
        "ipv4_dns_primary": dns4[0] if dns4 else None,
        "ipv4_dns_secondary": dns4[1] if len(dns4) > 1 else None,
        "ipv6_address": str(item.get("connIPv6Address") or "").strip(),
        "ipv6_gateway": str(item.get("connIPv6Gateway") or "").strip(),
        "ipv6_prefix": str(item.get("connIPv6Prefix") or "").strip(),
        "ipv6_dns_primary": dns6[0] if dns6 else None,
        "ipv6_dns_secondary": dns6[1] if len(dns6) > 1 else None,
        "ipv6_lifetime": lifetime,
        "ipv6_transition": transition,
        "aftr_gateway": str(item.get("X_TP_DsliteAftrServer") or "").strip() or None,
        "uptime_ipv4_seconds": parse_router_int(item.get("X_TP_Uptime")),
        "uptime_ipv6_seconds": parse_router_int(item.get("X_TP_UptimeV6")),
        "enabled": str(item.get("enable", "0")) == "1",
    }


def pick_primary_wan(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not entries:
        return None
    candidates = _rank_wan_candidates(entries, require_enabled=True)
    if not candidates:
        candidates = _rank_wan_candidates(entries, require_enabled=False)
    if not candidates:
        return wan_summary_dict(entries[0])
    candidates.sort(key=lambda entry: entry[0], reverse=True)
    return candidates[0][1]


def _rank_wan_candidates(
    entries: list[dict[str, Any]],
    *,
    require_enabled: bool,
) -> list[tuple[Any, dict[str, Any]]]:
    candidates: list[tuple[Any, dict[str, Any]]] = []
    mode_priority = {"VDSL": 0, "PTM": 1, "DSL": 2, "ADSL": 3, "EWAN": 4, "SFP": 5, "USB": 9}
    for item in entries:
        if require_enabled and str(item.get("enable", "0")) != "1":
            continue
        summary = wan_summary_dict(item)
        status_score = 0
        for status in (summary["ipv4_status"], summary["ipv6_status"]):
            lowered = status.lower()
            if lowered == "connected":
                status_score = max(status_score, 3)
            elif lowered == "connecting":
                status_score = max(status_score, 2)
        if summary["ipv4_address"] not in {"", "0.0.0.0"}:
            status_score = max(status_score, 3)
        if summary["ipv6_address"] not in {"", "::"}:
            status_score = max(status_score, 3)
        uptime = max(summary["uptime_ipv4_seconds"] or 0, summary["uptime_ipv6_seconds"] or 0)
        if status_score == 0 and uptime == 0 and require_enabled:
            continue
        priority = mode_priority.get(summary["access_mode"].upper(), 6)
        candidates.append(((status_score, uptime, -priority), summary))
    return candidates


def lan_summary_dict(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "mac": normalize_mac(str(item.get("MACAddress") or "")),
        "ipv4_address": str(item.get("IPAddress") or "").strip(),
        "ipv4_netmask": str(item.get("IPSubnetMask") or "").strip(),
        "dhcp_enabled": str(item.get("DHCPv4Enable", "0")) == "1",
        "ipv6_address": str(item.get("IPv6Address") or "").strip(),
        "ipv6_prefix": str(item.get("IPv6SitePrefix") or "").strip(),
    }


def wifi_radio_summary(item: dict[str, Any]) -> dict[str, Any]:
    mode = str(item.get("primaryModeEnabled") or item.get("standard") or "").strip()
    encryption = str(item.get("primaryWPAWPA2EncryptionMode") or "").strip()
    security = " ".join(part for part in (mode, encryption) if part) or "unknown"
    channel_width = str(item.get("currentBandwidth") or item.get("bandwidth") or "").strip() or None
    if str(item.get("autoChannel", "0")) == "1" and item.get("channel"):
        channel = f"Automatisch({item.get('channel')})"
    else:
        channel = str(item.get("channel") or "").strip() or None
    return {
        "band": str(item.get("band") or "unknown").strip(),
        "enabled": str(item.get("primaryEnable", "0")) == "1",
        "ssid": str(item.get("primarySSID") or "").strip(),
        "bssid": normalize_mac(str(item.get("primaryBSSID") or "")),
        "mode": str(item.get("standard") or "").strip(),
        "security": security,
        "channel": channel,
        "channel_width": channel_width,
    }


class Vx800vEXClientGCM:
    """VX800v-specific EX/GCM client with chunked-safe HTTP reads."""

    def __init__(
        self, host: str, password: str, username: str, logger, verify_ssl: bool, timeout: int
    ):
        from tplinkrouterc6u.client.ex import TPLinkEXClientGCM

        self._inner = TPLinkEXClientGCM(host, password, username, logger, verify_ssl, timeout)
        install_vx_chunked_request(self._inner)
        self._login_preview: str | None = None

    def __getattr__(self, name: str):
        return getattr(self._inner, name)

    @property
    def __class__(self):
        return self._inner.__class__

    def _request(self, url, method="POST", data_str=None, encrypt=False, is_login=False):
        return vx_chunked_request(self._inner, url, method, data_str, encrypt, is_login)

    def _req_login(self) -> None:
        from tplinkrouterc6u.common.exception import ClientException

        login_data = build_vx_login_payload(self._inner.username, self._inner.password)
        sign, data, tag = self._inner._prepare_data(login_data, True)
        request_data = f"sign={sign}\r\ndata={data}\r\ntag={tag}\r\n"
        url = f"{self._inner.host}/cgi_gdpr?9"
        code, response = vx_chunked_request(self._inner, url, data_str=request_data)
        if code != 200 or not response:
            raise ClientException(
                f"VX800v login failed: HTTP {code} from /cgi_gdpr. "
                f"Preview: {redact(response[:200] if response else 'empty')}"
            )

        try:
            decrypted = self._inner._encryption.aes_decrypt(response)
        except Exception as exc:  # noqa: BLE001
            raise ClientException(
                f"VX800v login failed: could not decrypt response ({exc}). "
                f"Raw preview: {redact(response[:120])}"
            ) from exc

        self._login_preview = redact(decrypted[:500])
        ret_code, preview = parse_js_ret(decrypted)
        if ret_code == self._inner.HTTP_RET_OK:
            return
        if ret_code == self._inner.HTTP_ERR_USER_PWD_NOT_CORRECT:
            raise ClientException(
                "VX800v login failed: wrong username/password "
                f"(username={self._inner.username!r}). Response preview: {preview}"
            )
        if ret_code is not None:
            raise ClientException(
                f"VX800v login failed: router returned $.ret={ret_code} "
                f"(username={self._inner.username!r}). Response preview: {preview}"
            )
        raise ClientException(
            "VX800v login failed: unexpected login response format. "
            f"Preview: {preview or self._login_preview or 'empty'}"
        )

    def get_status(self):
        """VX800v status: fetch OIDs individually; batched req_act drops empty responses."""
        from tplinkrouterc6u.common.dataclass import Device, Status
        from tplinkrouterc6u.common.helper import get_ip, get_mac
        from tplinkrouterc6u.common.package_enum import Connection

        inner = self._inner
        ActItem = inner.ActItem
        status = Status()

        lan = vx_req_act_data(
            inner, ActItem(ActItem.GL, "DEV2_ADT_LAN", attrs=["MACAddress", "IPAddress"])
        )
        if isinstance(lan, list) and lan:
            lan = lan[0]
        if isinstance(lan, dict):
            status._lan_macaddr = get_mac(lan.get("MACAddress", "00:00:00:00:00:00"))
            status._lan_ipv4_addr = get_ip(lan.get("IPAddress", "0.0.0.0"))

        wan = vx_wan_entries(inner)
        for item in wan:
            if not wan_entry_connected(item):
                continue
            mac = first_field(item, WAN_MAC_KEYS)
            if mac:
                status._wan_macaddr = get_mac(mac)
            ip = first_field(item, WAN_IP_KEYS)
            if ip:
                status._wan_ipv4_addr = get_ip(ip)
            gw = first_field(item, WAN_GW_KEYS)
            if gw:
                status._wan_ipv4_gateway = get_ip(gw)

        apply_wifi_status(
            status, vx_req_act_data(inner, ActItem(ActItem.GL, "DEV2_ADT_WIFI_COMMON"))
        )

        devices: dict[str, Device] = {}
        for val in vx_fetch_host_entries(inner):
            client_dict = host_entry_to_client_dict(inner, val)
            if client_dict is None:
                continue
            conn = inner.CLIENT_TYPES.get(int(val.get("X_TP_LanConnType", -1)))
            if conn is not None:
                if conn == Connection.WIRED:
                    status.wired_total += 1
                elif conn.is_guest_wifi():
                    status.guest_clients_total += 1
                elif conn.is_host_wifi():
                    status.wifi_clients_total += 1
                devices[client_dict["mac"]] = Device(
                    conn,
                    get_mac(val["physAddress"]),
                    get_ip(val["IPAddress"]),
                    val.get("hostName", ""),
                )

        status.cpu_usage, status.mem_usage = parse_cpu_mem_cgi(inner)
        if status.cpu_usage is None and status.mem_usage is None:
            status.cpu_usage, status.mem_usage = vx_cpu_mem(inner)
        status.devices = list(devices.values())
        status.clients_total = (
            status.wired_total + status.wifi_clients_total + status.guest_clients_total
        )
        return status

    def get_ipv4_status(self):
        from tplinkrouterc6u.common.dataclass import IPv4Status
        from tplinkrouterc6u.common.helper import get_ip, get_mac

        inner = self._inner
        ipv4_status = IPv4Status()

        lan = vx_fetch_act_variants(
            inner,
            "DEV2_ADT_LAN",
            attrs=["MACAddress", "IPAddress", "IPSubnetMask", "DHCPv4Enable"],
        )
        if isinstance(lan, list) and lan:
            lan = lan[0]
        if isinstance(lan, dict):
            mac = first_field(lan, WAN_MAC_KEYS) or lan.get("MACAddress")
            if mac:
                ipv4_status._lan_macaddr = get_mac(mac)
            ip = first_field(lan, WAN_IP_KEYS) or lan.get("IPAddress")
            if ip:
                ipv4_status._lan_ipv4_ipaddr = get_ip(ip)
            mask = lan.get("IPSubnetMask")
            if mask:
                ipv4_status._lan_ipv4_netmask = get_ip(mask)
            if lan.get("DHCPv4Enable") is not None:
                ipv4_status.lan_ipv4_dhcp_enable = bool(int(lan["DHCPv4Enable"]))

        for item in vx_wan_entries(inner):
            if not wan_entry_connected(item):
                continue
            mac = first_field(item, WAN_MAC_KEYS)
            if mac:
                ipv4_status._wan_macaddr = get_mac(mac)
            ip = first_field(item, WAN_IP_KEYS)
            if ip:
                ipv4_status._wan_ipv4_ipaddr = get_ip(ip)
            gw = first_field(item, WAN_GW_KEYS)
            if gw:
                ipv4_status._wan_ipv4_gateway = get_ip(gw)
            if item.get("name"):
                ipv4_status._wan_ipv4_conntype = str(item["name"])
            mask = item.get("connIPv4SubnetMask") or item.get("subnetMask")
            if mask:
                ipv4_status._wan_ipv4_netmask = get_ip(mask)
            dns = str(item.get("connIPv4DnsServer") or item.get("DNSServers") or "").split(",")
            if dns and dns[0]:
                ipv4_status._wan_ipv4_pridns = get_ip(dns[0])
            if len(dns) > 1 and dns[1]:
                ipv4_status._wan_ipv4_snddns = get_ip(dns[1])
            break

        return ipv4_status

    def get_ipv6_status(self):
        from tplinkrouterc6u.common.dataclass import IPv6Status
        from tplinkrouterc6u.common.helper import get_ipv6

        inner = self._inner
        ipv6_status = IPv6Status()
        for item in vx_wan_entries(inner):
            if (
                item.get("X_TP_IPv6Enabled") is None
                and item.get("X_TP_ExternalIPv6Address") is None
            ):
                continue
            if item.get("X_TP_IPv6Enabled") is not None:
                ipv6_status.wan_ipv6_enabled = bool(int(item.get("X_TP_IPv6Enabled", "0")))
            if item.get("X_TP_IPv6ConnStatus"):
                ipv6_status._wan_ipv6_conn_status = str(item["X_TP_IPv6ConnStatus"])
            if item.get("X_TP_ExternalIPv6Address"):
                ipv6_status._wan_ipv6_addr = get_ipv6(item["X_TP_ExternalIPv6Address"])
            if item.get("X_TP_DefaultIPv6Gateway"):
                ipv6_status._wan_ipv6_gateway = get_ipv6(item["X_TP_DefaultIPv6Gateway"])
            dns = str(item.get("X_TP_IPv6DNSServers") or "").split(",")
            if dns and dns[0]:
                ipv6_status._wan_ipv6_pridns = get_ipv6(dns[0])
            if len(dns) > 1 and dns[1]:
                ipv6_status._wan_ipv6_snddns = get_ipv6(dns[1])
            break
        return ipv6_status
