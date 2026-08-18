"""Prometheus metric definitions and update helpers."""

from __future__ import annotations

from typing import Any

from prometheus_client import Gauge, Info

NAMESPACE = "tplink"

tplink_up = Gauge(
    "up",
    "Router reachability status (1 = up, 0 = down)",
    ["device"],
    namespace=NAMESPACE,
)

tplink_info = Info(
    "info",
    "Router information labels",
    ["device"],
    namespace=NAMESPACE,
)

tplink_router_cpu_usage = Gauge(
    "router_cpu_usage",
    "CPU usage as a fraction (0-1)",
    ["device"],
    namespace=NAMESPACE,
)
tplink_router_cpu_percent = Gauge(
    "router_cpu_percent",
    "CPU usage percentage",
    ["device"],
    namespace=NAMESPACE,
)
tplink_router_mem_usage = Gauge(
    "router_mem_usage",
    "Memory usage as a fraction (0-1)",
    ["device"],
    namespace=NAMESPACE,
)
tplink_router_mem_percent = Gauge(
    "router_mem_percent",
    "Memory usage percentage",
    ["device"],
    namespace=NAMESPACE,
)

tplink_router_connected_clients = Gauge(
    "router_connected_clients",
    "Number of connected LAN clients",
    ["device"],
    namespace=NAMESPACE,
)
tplink_client_up = Gauge(
    "client_up",
    "LAN client is connected (1 = up)",
    ["device", "mac", "ip", "hostname", "connection"],
    namespace=NAMESPACE,
)
tplink_client_lease_seconds = Gauge(
    "client_lease_seconds",
    "DHCP lease remaining in seconds",
    ["device", "mac"],
    namespace=NAMESPACE,
)

tplink_dsl_link_up = Gauge(
    "dsl_link_up",
    "DSL link up from showDslStats (1 = up)",
    ["device", "mode"],
    namespace=NAMESPACE,
)
tplink_dsl_info = Gauge(
    "dsl_info",
    "DSL line info from showDslStats",
    ["device", "mode", "profile"],
    namespace=NAMESPACE,
)
tplink_dsl_sync_rate_kbps = Gauge(
    "dsl_sync_rate_kbps",
    "DSL sync rate in kbps from showDslStats",
    ["device", "direction"],
    namespace=NAMESPACE,
)
tplink_dsl_snr_db = Gauge(
    "dsl_snr_db",
    "DSL SNR in dB from showDslStats",
    ["device", "direction"],
    namespace=NAMESPACE,
)
tplink_dsl_link_uptime_seconds = Gauge(
    "dsl_link_uptime_seconds",
    "DSL link uptime in seconds from showDslStats",
    ["device"],
    namespace=NAMESPACE,
)

tplink_wifi_connected_clients = Gauge(
    "wifi_connected_clients",
    "Number of connected WLAN clients",
    ["device"],
    namespace=NAMESPACE,
)
tplink_wifi_client_up = Gauge(
    "wifi_client_up",
    "WLAN client is connected (1 = up)",
    ["device", "mac", "hostname", "band", "ap_type"],
    namespace=NAMESPACE,
)
tplink_wifi_client_signal_dbm = Gauge(
    "wifi_client_signal_dbm",
    "WLAN client signal strength in dBm",
    ["device", "mac", "band"],
    namespace=NAMESPACE,
)
tplink_wifi_client_bytes_sent_total = Gauge(
    "wifi_client_bytes_sent_total",
    "WLAN client bytes sent",
    ["device", "mac", "band"],
    namespace=NAMESPACE,
)
tplink_wifi_client_bytes_received_total = Gauge(
    "wifi_client_bytes_received_total",
    "WLAN client bytes received",
    ["device", "mac", "band"],
    namespace=NAMESPACE,
)
tplink_wifi_client_packets_sent_total = Gauge(
    "wifi_client_packets_sent_total",
    "WLAN client packets sent",
    ["device", "mac", "band"],
    namespace=NAMESPACE,
)
tplink_wifi_client_packets_received_total = Gauge(
    "wifi_client_packets_received_total",
    "WLAN client packets received",
    ["device", "mac", "band"],
    namespace=NAMESPACE,
)

tplink_system_uptime_seconds = Gauge(
    "system_uptime_seconds",
    "Router system uptime in seconds",
    ["device"],
    namespace=NAMESPACE,
)
tplink_wan_primary_info = Gauge(
    "wan_primary_info",
    "Primary WAN connection info",
    ["device", "name", "conn_type", "access_mode", "ipv6_status", "ipv6_transition", "aftr_gateway"],
    namespace=NAMESPACE,
)
tplink_wan_ipv4_uptime_seconds = Gauge(
    "wan_ipv4_uptime_seconds",
    "Primary WAN IPv4 uptime in seconds",
    ["device", "name"],
    namespace=NAMESPACE,
)
tplink_wan_ipv6_uptime_seconds = Gauge(
    "wan_ipv6_uptime_seconds",
    "Primary WAN IPv6 uptime in seconds",
    ["device", "name"],
    namespace=NAMESPACE,
)
tplink_lan_info = Gauge(
    "lan_info",
    "LAN interface info",
    ["device", "ipv4", "mac", "netmask", "dhcp_enabled"],
    namespace=NAMESPACE,
)
tplink_lan_ipv6_info = Gauge(
    "lan_ipv6_info",
    "LAN IPv6 info from overview",
    ["device", "ipv6_address", "ipv6_prefix"],
    namespace=NAMESPACE,
)

tplink_wifi_radio_up = Gauge(
    "wifi_radio_up",
    "Wi-Fi radio enabled (1 = on)",
    ["device", "band", "ssid"],
    namespace=NAMESPACE,
)
tplink_wifi_radio_channel_info = Gauge(
    "wifi_radio_channel_info",
    "Wi-Fi radio channel info",
    ["device", "band", "channel"],
    namespace=NAMESPACE,
)
tplink_wifi_radio_info = Gauge(
    "wifi_radio_info",
    "Wi-Fi radio overview info",
    ["device", "band", "ssid", "bssid", "mode", "security", "channel_width"],
    namespace=NAMESPACE,
)

# Dynamic counter metrics from showDslStats (crc, es, ses, etc.)
_dsl_counter_metrics: dict[str, Gauge] = {}

_known_lan_clients: dict[str, set[str]] = {}
_known_wifi_clients: dict[str, set[tuple[str, str]]] = {}


def _dsl_counter_metric(name: str) -> Gauge:
    if name not in _dsl_counter_metrics:
        _dsl_counter_metrics[name] = Gauge(
            f"dsl_{name}_total",
            f"DSL {name} counter since link from showDslStats",
            ["device", "direction", "window"],
            namespace=NAMESPACE,
        )
    return _dsl_counter_metrics[name]


def reset_dynamic_metrics(device: str) -> None:
    """Clear tracked per-client metrics after repeated poll failures."""
    for mac in _known_lan_clients.get(device, set()):
        try:
            tplink_client_up.labels(
                device=device, mac=mac, ip="0.0.0.0", hostname="unknown", connection="unknown"
            ).remove()
            tplink_client_lease_seconds.labels(device=device, mac=mac).remove()
        except KeyError:
            pass
    _known_lan_clients[device] = set()

    for mac, band in _known_wifi_clients.get(device, set()):
        try:
            tplink_wifi_client_up.labels(
                device=device, mac=mac, hostname="unknown", band=band, ap_type="unknown"
            ).remove()
            tplink_wifi_client_signal_dbm.labels(device=device, mac=mac, band=band).remove()
            tplink_wifi_client_bytes_sent_total.labels(device=device, mac=mac, band=band).remove()
            tplink_wifi_client_bytes_received_total.labels(
                device=device, mac=mac, band=band
            ).remove()
            tplink_wifi_client_packets_sent_total.labels(device=device, mac=mac, band=band).remove()
            tplink_wifi_client_packets_received_total.labels(
                device=device, mac=mac, band=band
            ).remove()
        except KeyError:
            pass
    _known_wifi_clients[device] = set()


def update_metrics(device: str, metrics: dict[str, Any], *, client_class: str) -> None:
    """Update all Prometheus metrics from collected router data."""
    status = metrics.get("status") or metrics.get("get_status") or {}
    cgi = metrics.get("cgi") or {}

    cpu_usage = cgi.get("cpu_usage")
    mem_usage = cgi.get("mem_usage")
    if cpu_usage is None and isinstance(status, dict):
        cpu_usage = status.get("cpu_usage")
    if mem_usage is None and isinstance(status, dict):
        mem_usage = status.get("mem_usage")

    if isinstance(cpu_usage, (int, float)):
        tplink_router_cpu_usage.labels(device=device).set(cpu_usage)
        tplink_router_cpu_percent.labels(device=device).set(cpu_usage * 100)
    if isinstance(mem_usage, (int, float)):
        tplink_router_mem_usage.labels(device=device).set(mem_usage)
        tplink_router_mem_percent.labels(device=device).set(mem_usage * 100)

    overview = metrics.get("overview") or {}
    system = overview.get("system") or {} if isinstance(overview, dict) else {}
    firmware = metrics.get("get_firmware") or metrics.get("firmware") or {}
    info_labels = {
        "model": str(system.get("model") or firmware.get("model") or "unknown"),
        "firmware": str(system.get("software_version") or firmware.get("version") or "unknown"),
        "hardware": str(system.get("hardware_version") or "unknown"),
        "auth_client": client_class,
    }
    tplink_info.labels(device=device).info(info_labels)

    clients = metrics.get("clients")
    connected_clients = metrics.get("connected_clients")
    client_entries: list[dict[str, Any]] = []
    if isinstance(connected_clients, list):
        tplink_router_connected_clients.labels(device=device).set(len(connected_clients))
        client_entries = [entry for entry in connected_clients if isinstance(entry, dict)]
    elif isinstance(clients, list):
        tplink_router_connected_clients.labels(device=device).set(len(clients))
        client_entries = [entry for entry in clients if isinstance(entry, dict)]

    if client_entries:
        current_macs: set[str] = set()
        for entry in client_entries:
            if not isinstance(entry, dict):
                continue
            mac = str(entry.get("mac", "unknown"))
            current_macs.add(mac)
            tplink_client_up.labels(
                device=device,
                mac=mac,
                ip=str(entry.get("ip", "0.0.0.0")),
                hostname=str(entry.get("hostname", "unknown")),
                connection=str(entry.get("connection", "unknown")),
            ).set(1)
            lease = entry.get("lease_seconds")
            if isinstance(lease, int):
                tplink_client_lease_seconds.labels(device=device, mac=mac).set(lease)
        _known_lan_clients[device] = current_macs
    elif not isinstance(connected_clients, list) and isinstance(status, dict):
        devices = status.get("devices") or []
        if isinstance(devices, list):
            tplink_router_connected_clients.labels(device=device).set(len(devices))

    dsl = cgi.get("dsl") if isinstance(cgi, dict) else None
    if isinstance(dsl, dict) and dsl.get("status"):
        mode = str(dsl.get("mode") or "unknown")
        profile = str(dsl.get("profile") or "unknown")
        tplink_dsl_link_up.labels(device=device, mode=mode).set(1 if dsl.get("link_up") else 0)
        if dsl.get("profile"):
            tplink_dsl_info.labels(device=device, mode=mode, profile=profile).set(1)
        sync = dsl.get("sync_rate_kbps") or {}
        if isinstance(sync, dict):
            for direction, kbps in sync.items():
                if isinstance(kbps, int):
                    tplink_dsl_sync_rate_kbps.labels(device=device, direction=direction).set(kbps)
        snr = dsl.get("snr_db") or {}
        if isinstance(snr, dict):
            for direction, value in snr.items():
                if isinstance(value, (int, float)):
                    tplink_dsl_snr_db.labels(device=device, direction=direction).set(value)
        uptime = dsl.get("link_uptime_seconds")
        if isinstance(uptime, int):
            tplink_dsl_link_uptime_seconds.labels(device=device).set(uptime)
        counters = dsl.get("counters_since_link") or {}
        if isinstance(counters, dict):
            for name, values in counters.items():
                if not isinstance(values, dict):
                    continue
                metric = _dsl_counter_metric(name)
                for direction, count in values.items():
                    if isinstance(count, int):
                        metric.labels(device=device, direction=direction, window="since_link").set(
                            count
                        )

    wifi_clients = metrics.get("wifi_clients")
    if isinstance(wifi_clients, list):
        tplink_wifi_connected_clients.labels(device=device).set(len(wifi_clients))
        current_wifi: set[tuple[str, str]] = set()
        for entry in wifi_clients:
            if not isinstance(entry, dict):
                continue
            mac = str(entry.get("mac", "unknown"))
            band = str(entry.get("band", "unknown"))
            current_wifi.add((mac, band))
            tplink_wifi_client_up.labels(
                device=device,
                mac=mac,
                hostname=str(entry.get("hostname", "unknown")),
                band=band,
                ap_type=str(entry.get("ap_type", "unknown")),
            ).set(1)
            signal_dbm = entry.get("signal_dbm")
            if isinstance(signal_dbm, int):
                tplink_wifi_client_signal_dbm.labels(device=device, mac=mac, band=band).set(
                    signal_dbm
                )
            for prom_metric, field in (
                (tplink_wifi_client_bytes_sent_total, "bytes_sent"),
                (tplink_wifi_client_bytes_received_total, "bytes_received"),
                (tplink_wifi_client_packets_sent_total, "packets_sent"),
                (tplink_wifi_client_packets_received_total, "packets_received"),
            ):
                value = entry.get(field)
                if isinstance(value, int):
                    prom_metric.labels(device=device, mac=mac, band=band).set(value)
        _known_wifi_clients[device] = current_wifi

    if isinstance(overview, dict):
        uptime = system.get("uptime_seconds")
        if isinstance(uptime, int):
            tplink_system_uptime_seconds.labels(device=device).set(uptime)

        primary_wan = (overview.get("wan") or {}).get("primary") or {}
        if isinstance(primary_wan, dict) and primary_wan:
            wan_name = str(
                primary_wan.get("name")
                or primary_wan.get("conn_type")
                or primary_wan.get("access_mode")
                or "primary"
            ).strip() or "primary"
            tplink_wan_primary_info.labels(
                device=device,
                name=wan_name,
                conn_type=str(primary_wan.get("conn_type") or "unknown"),
                access_mode=str(primary_wan.get("access_mode") or "unknown"),
                ipv6_status=str(primary_wan.get("ipv6_status") or "unknown"),
                ipv6_transition=str(primary_wan.get("ipv6_transition") or "none"),
                aftr_gateway=str(primary_wan.get("aftr_gateway") or "none"),
            ).set(1)
            for key, prom_metric in (
                ("uptime_ipv4_seconds", tplink_wan_ipv4_uptime_seconds),
                ("uptime_ipv6_seconds", tplink_wan_ipv6_uptime_seconds),
            ):
                value = primary_wan.get(key)
                if isinstance(value, int):
                    prom_metric.labels(device=device, name=wan_name).set(value)

        lan = overview.get("lan") or {}
        if isinstance(lan, dict) and (lan.get("ipv4_address") or lan.get("mac")):
            tplink_lan_info.labels(
                device=device,
                ipv4=str(lan.get("ipv4_address") or "unknown"),
                mac=str(lan.get("mac") or "unknown"),
                netmask=str(lan.get("ipv4_netmask") or "unknown"),
                dhcp_enabled="true" if lan.get("dhcp_enabled") else "false",
            ).set(1)
            if lan.get("ipv6_address") or lan.get("ipv6_prefix"):
                tplink_lan_ipv6_info.labels(
                    device=device,
                    ipv6_address=str(lan.get("ipv6_address") or "unknown"),
                    ipv6_prefix=str(lan.get("ipv6_prefix") or "unknown"),
                ).set(1)

        for radio in overview.get("wifi_radios") or []:
            if not isinstance(radio, dict):
                continue
            band = str(radio.get("band") or "unknown")
            ssid = str(radio.get("ssid") or "unknown")
            tplink_wifi_radio_up.labels(device=device, band=band, ssid=ssid).set(
                1 if radio.get("enabled") else 0
            )
            channel = radio.get("channel")
            if channel:
                tplink_wifi_radio_channel_info.labels(
                    device=device, band=band, channel=str(channel)
                ).set(1)
            tplink_wifi_radio_info.labels(
                device=device,
                band=band,
                ssid=ssid,
                bssid=str(radio.get("bssid") or "unknown"),
                mode=str(radio.get("mode") or "unknown"),
                security=str(radio.get("security") or "unknown"),
                channel_width=str(radio.get("channel_width") or "unknown"),
            ).set(1)
