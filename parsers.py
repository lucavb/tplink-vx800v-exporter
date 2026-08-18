"""Metric collection from router CGI and OID endpoints."""

from __future__ import annotations

import time
from typing import Any

from logging_utils import ProbeLog, redact
from router import (
    DSLITE_ATTRS,
    LAN_SUMMARY_ATTRS,
    WAN_SUMMARY_ATTRS,
    WIFI_RADIO_ATTRS,
    fetch_show_dsl_stats,
    hostnames_by_mac,
    lan_summary_dict,
    parse_cpu_mem_cgi,
    parse_dsl_stats,
    parse_router_int,
    pick_primary_wan,
    vx_fetch_oid_get,
    vx_fetch_oid_gl_list,
    vx_fetch_wifi_clients,
    vx_wan_entries,
    wan_summary_dict,
    wifi_client_to_dict,
    wifi_radio_summary,
)


def collect_cgi_metrics(client: Any, log: ProbeLog) -> dict[str, Any]:
    """Netzplan CGI endpoints: CPU, memory, showDslStats."""
    out: dict[str, Any] = {"steps": []}
    router = client._inner if hasattr(client, "_inner") else client

    started = log.step_start("cgi.cpu_mem")
    try:
        cpu_usage, mem_usage = parse_cpu_mem_cgi(router)
        out["cpu_usage"] = cpu_usage
        out["mem_usage"] = mem_usage
        out["steps"].append(
            {
                "step": "cgi.cpu_mem",
                "seconds": round(time.monotonic() - started, 2),
                "ok": True,
                "detail": f"cpu={cpu_usage} mem={mem_usage}",
            }
        )
        log.step_end("cgi.cpu_mem", started, out["steps"][-1]["detail"])
    except Exception as exc:  # noqa: BLE001
        out["steps"].append(
            {
                "step": "cgi.cpu_mem",
                "seconds": round(time.monotonic() - started, 2),
                "ok": False,
                "error": redact(str(exc)),
            }
        )
        log.step_fail("cgi.cpu_mem", started, exc)

    def record(step: str, started_at: float, ok: bool, **detail: Any) -> None:
        out["steps"].append(
            {
                "step": step,
                "seconds": round(time.monotonic() - started_at, 2),
                "ok": ok,
                **detail,
            }
        )

    started = log.step_start("cgi.showDslStats")
    try:
        _, raw = fetch_show_dsl_stats(router)
        dsl = parse_dsl_stats(raw)
        out["dsl"] = dsl
        link = dsl.get("status") or "unknown"
        record("cgi.showDslStats", started, True, detail=f"status={link}")
        log.step_end("cgi.showDslStats", started, f"status={link}")
    except Exception as exc:  # noqa: BLE001
        record("cgi.showDslStats", started, False, error=redact(str(exc)))
        log.step_fail("cgi.showDslStats", started, exc)

    return out


def collect_wifi_metrics(
    router: Any,
    log: ProbeLog,
    host_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """WLAN > Statistiken: refresh associations then read DEV2_ADT_WIFI_CLIENT."""
    out: dict[str, Any] = {"clients": [], "steps": []}
    hostnames = hostnames_by_mac(host_entries)
    started = log.step_start("wifi.DEV2_ADT_WIFI_CLIENT")

    try:
        clients: list[dict[str, Any]] = []
        for entry in vx_fetch_wifi_clients(router, refresh=True):
            client_dict = wifi_client_to_dict(entry, hostnames)
            if client_dict:
                clients.append(client_dict)
        out["clients"] = clients
        out["steps"].append(
            {
                "step": "wifi.DEV2_ADT_WIFI_CLIENT",
                "seconds": round(time.monotonic() - started, 2),
                "ok": True,
                "detail": f"count={len(clients)}",
            }
        )
        log.step_end("wifi.DEV2_ADT_WIFI_CLIENT", started, f"count={len(clients)}")
    except Exception as exc:  # noqa: BLE001
        out["steps"].append(
            {
                "step": "wifi.DEV2_ADT_WIFI_CLIENT",
                "seconds": round(time.monotonic() - started, 2),
                "ok": False,
                "error": redact(str(exc)),
            }
        )
        log.step_fail("wifi.DEV2_ADT_WIFI_CLIENT", started, exc)

    return out


def collect_status_overview(router: Any, log: ProbeLog) -> dict[str, Any]:
    """Erweiterte Einstellungen > Übersicht (status.htm) summary metrics."""
    out: dict[str, Any] = {"steps": []}
    started = log.step_start("overview.status")

    try:
        dev = vx_fetch_oid_get(
            router,
            "DEV2_DEV_INFO",
            attrs=["upTime", "softwareVersion", "hardwareVersion", "modelName"],
        )
        if dev:
            out["system"] = {
                "uptime_seconds": parse_router_int(dev.get("upTime")),
                "software_version": str(dev.get("softwareVersion") or "").strip(),
                "hardware_version": str(dev.get("hardwareVersion") or "").strip(),
                "model": str(dev.get("modelName") or "").strip(),
            }

        lan_entries = vx_fetch_oid_gl_list(
            router,
            "DEV2_ADT_LAN",
            attrs=list(LAN_SUMMARY_ATTRS),
        )
        if lan_entries:
            out["lan"] = lan_summary_dict(lan_entries[0])

        wan_entries = vx_fetch_oid_gl_list(router, "DEV2_ADT_WAN", attrs=list(WAN_SUMMARY_ATTRS))
        if not wan_entries:
            wan_entries = vx_wan_entries(router)
        out["wan"] = {
            "connections": [wan_summary_dict(item) for item in wan_entries],
            "primary": pick_primary_wan(wan_entries),
        }

        dslite_entries = vx_fetch_oid_gl_list(
            router,
            "DEV2_DSLITE_INTFSET",
            attrs=list(DSLITE_ATTRS),
        )
        if dslite_entries:
            dslite = dslite_entries[0]
            out["dslite"] = {
                "enabled": str(dslite.get("enable", "0")) == "1",
                "status": str(dslite.get("status") or "").strip(),
                "aftr_name": str(dslite.get("endpointName") or "").strip() or None,
                "aftr_address": str(dslite.get("endpointAddressInUse") or "").strip() or None,
                "wan_connection": str(dslite.get("X_TP_ConnName") or "").strip() or None,
            }
            primary = out.get("wan", {}).get("primary") or {}
            if primary and not primary.get("aftr_gateway") and out["dslite"].get("aftr_name"):
                primary = dict(primary)
                primary["aftr_gateway"] = out["dslite"]["aftr_name"]
                primary["ipv6_transition"] = "DS-Lite"
                out["wan"]["primary"] = primary

        wifi_entries = vx_fetch_oid_gl_list(
            router, "DEV2_ADT_WIFI_COMMON", attrs=list(WIFI_RADIO_ATTRS)
        )
        out["wifi_radios"] = [wifi_radio_summary(item) for item in wifi_entries]

        out["steps"].append(
            {
                "step": "overview.status",
                "seconds": round(time.monotonic() - started, 2),
                "ok": True,
                "detail": (
                    f"wan={((out.get('wan') or {}).get('primary') or {}).get('name', '?')}, "
                    f"wifi={len(out.get('wifi_radios') or [])}"
                ),
            }
        )
        log.step_end("overview.status", started, out["steps"][-1]["detail"])
    except Exception as exc:  # noqa: BLE001
        out["steps"].append(
            {
                "step": "overview.status",
                "seconds": round(time.monotonic() - started, 2),
                "ok": False,
                "error": redact(str(exc)),
            }
        )
        log.step_fail("overview.status", started, exc)

    return out
