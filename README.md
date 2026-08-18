# TP-Link VX800v Exporter

Prometheus exporter for TP-Link VX800v (Aginet) VDSL modem routers.

Validated on **VX800v v1.0, firmware 800.0.20**. Other Aginet VX* models may work but are untested.

## Supported Devices

- TP-Link VX800v (Aginet firmware)
- Potentially other Aginet VX* routers using GCM/GDPR login

## Installation

### Using uv

```bash
uv sync
export TPLINK_ROUTER_PASSWORD='your-router-password'
uv run tplink-vx800v-exporter
```

### Using Docker

```bash
docker run -d \
  --name tplink-vx800v-exporter \
  -p 9105:9105 \
  -e TPLINK_ROUTER_HOST=https://192.168.1.1 \
  -e TPLINK_ROUTER_PASSWORD='your-router-password' \
  ghcr.io/lucavb/tplink-vx800v-exporter:latest
```

### Docker Compose

```yaml
services:
  tplink-vx800v-exporter:
    image: ghcr.io/lucavb/tplink-vx800v-exporter:latest
    ports:
      - "9105:9105"
    environment:
      - TPLINK_ROUTER_HOST=https://192.168.1.1
      - TPLINK_ROUTER_PASSWORD=${TPLINK_ROUTER_PASSWORD}
    restart: unless-stopped
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TPLINK_ROUTER_PASSWORD` | _required_ | Router password (env only — never pass on CLI) |
| `TPLINK_ROUTER_HOST` | `https://192.168.1.1` | Router URL |
| `TPLINK_ROUTER_USER` | `user` | Login username (VX Aginet default: `user`, not `admin`) |
| `TPLINK_ROUTER_NAME` | hostname from URL | `device` label on all metrics |
| `METRICS_PORT` | `9105` | Prometheus `/metrics` port |
| `SCRAPE_INTERVAL` | `60` | Seconds between router polls |
| `TPLINK_ROUTER_TIMEOUT` | `60` | HTTP timeout in seconds |
| `TPLINK_ROUTER_VERIFY_SSL` | `false` | Verify router TLS certificate |
| `TPLINK_DEBUG` | `false` | Verbose debug logging |
| `STALE_AFTER_FAILURES` | `3` | Clear per-client metrics after N consecutive failures |
| `RECONNECT_AFTER_POLL_FAILURES` | `3` | Re-authenticate after N consecutive failures (0 = never) |
| `RECONNECT_BACKOFF_SECONDS` | `5` | Initial reconnect backoff |
| `RECONNECT_BACKOFF_MAX_SECONDS` | `120` | Max reconnect backoff |
| `EXIT_AFTER_SECONDS_WITHOUT_POLL_SUCCESS` | `0` | Exit if no successful poll for N seconds (k8s restart hook) |
| `EXIT_AFTER_CONSECUTIVE_INIT_FAILURES` | `0` | Exit after N failed login attempts |

## Metrics

All metrics use the `tplink_` prefix and a `device` label (from `TPLINK_ROUTER_NAME` or router hostname).

### Exporter

- `tplink_up` — router reachability (1 = up)
- `tplink_info` — model, firmware, hardware, auth client class

### System

- `tplink_router_cpu_usage` / `tplink_router_cpu_percent`
- `tplink_router_mem_usage` / `tplink_router_mem_percent`
- `tplink_system_uptime_seconds`

### WAN / LAN

- `tplink_wan_primary_info` — primary WAN (conn type, IPv6 status, DS-Lite transition, AFTR gateway)
- `tplink_wan_ipv4_uptime_seconds` / `tplink_wan_ipv6_uptime_seconds`
- `tplink_lan_info` — IPv4, MAC, netmask, DHCP
- `tplink_lan_ipv6_info` — LAN IPv6 address and prefix

DS-Lite note: there is no legacy `tplink_router_wan_connected` metric from IPv4 status. On DS-Lite setups, use `tplink_wan_primary_info` and IPv6 uptime metrics instead.

### DSL

DSL metrics come from `/cgi/showDslStats` (Netzwerk > DSL-Info):
`tplink_dsl_link_up`, `tplink_dsl_sync_rate_kbps`, `tplink_dsl_fec_total`,
`tplink_dsl_crc_total`, and related line statistics.

The duplicate `tplink_dsl_overview_*` OID family is intentionally omitted. On
firmware 800.0.20, those OIDs conflict with the dynamic client-list state and
cannot be collected reliably in the same polling session.

### Clients

- `tplink_router_connected_clients` — unique connected devices (LAN `DEV2_HOST_ENTRY` + WLAN `DEV2_ADT_WIFI_CLIENT`, merged by MAC)
- `tplink_wifi_connected_clients` — WLAN clients from `DEV2_ADT_WIFI_CLIENT` (after `ACT_WIFI_UPDATE_ALLASSOC`)
- Per-client gauges: `tplink_client_up`, `tplink_wifi_client_up`, signal, traffic counters

`tplink_client_up` uses the merged LAN+WLAN client list so WLAN-only devices appear in both totals and per-client metrics.

### Wi-Fi

- `tplink_wifi_radio_up` / `tplink_wifi_radio_channel_info`
- `tplink_wifi_radio_info` — SSID, BSSID, mode, security, channel width per band

## Security

- Password is read from `TPLINK_ROUTER_PASSWORD` environment variable only
- Sensitive fields (`PPPPassword`, `primaryPSK`, etc.) are never fetched
- Internet/WAN config pages are not scraped
- Log output is redacted for tokens, passwords, and session IDs

## Debug Probe

One-shot CLI for testing without running the HTTP server:

```bash
export TPLINK_ROUTER_PASSWORD='your-router-password'
uv run scripts/tplink-vx800v-probe.py --prometheus
```

## Development

```bash
uv sync --dev
uv run ruff check .
uv run ruff format .
uv run pyright
docker build -t tplink-vx800v-exporter:test .
```

## License

MIT
