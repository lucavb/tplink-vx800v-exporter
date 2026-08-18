#!/usr/bin/env python3
"""One-shot probe for TP-Link VX800v routers (debug / script_exporter).

Reads credentials from the environment only — never pass the password on the
command line. Example:

  export TPLINK_ROUTER_PASSWORD='your-admin-password'
  uv run scripts/tplink-vx800v-probe.py --prometheus
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from prometheus_client import generate_latest

import config
from auth import (
    collect_router_metrics,
    connect_router,
    probe_unauthenticated,
    resolve_username,
)
from config import device_name
from logging_utils import ProbeLog, configure_tplink_logging
from metrics import update_metrics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=config.TPLINK_ROUTER_HOST)
    parser.add_argument("--user", default=config.TPLINK_ROUTER_USER)
    parser.add_argument("--client", default=config.TPLINK_ROUTER_CLIENT)
    parser.add_argument("--timeout", type=int, default=config.TPLINK_ROUTER_TIMEOUT)
    parser.add_argument("--debug", action="store_true", default=config.env_bool("TPLINK_DEBUG"))
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument(
        "--prometheus", action="store_true", help="print Prometheus text after auth"
    )
    parser.add_argument("--try-users", default=config.TPLINK_TRY_USERS)
    parser.add_argument(
        "--logout-first",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    parser.add_argument("--unauth-only", action="store_true")
    args = parser.parse_args()

    log = ProbeLog(args.debug)
    configure_tplink_logging(args.debug)
    verify_ssl = config.TPLINK_ROUTER_VERIFY_SSL
    password = os.environ.get("TPLINK_ROUTER_PASSWORD")

    unauth = probe_unauthenticated(args.host, verify_ssl, args.timeout, log)
    output: dict = {"unauthenticated": unauth}
    username = resolve_username(unauth.get("model"), args.user)
    try_users = None
    if args.try_users:
        try_users = [part.strip() for part in args.try_users.split(",")]

    busy = (unauth.get("cgis", {}).get("/cgi/getBusy") or {}).get("vars", {})
    logout_first = args.logout_first
    if logout_first is None:
        logout_first = busy.get("isLogined") == "1"

    if password and not args.unauth_only:
        auth_result: dict = {"metrics": {}}
        try:
            client, client_class = connect_router(
                args.host,
                password,
                username,
                verify_ssl,
                args.timeout,
                log,
                model=unauth.get("model"),
                forced_client=args.client,
                logout_first=logout_first,
                login_flags=unauth.get("login_flags"),
                try_users=try_users,
            )
            auth_result["client"] = client_class
            auth_result["username"] = username
            auth_result["metrics"] = collect_router_metrics(client, log)
            try:
                router = client._inner if hasattr(client, "_inner") else client
                router.logout()
            except Exception:
                pass
        except Exception as exc:
            auth_result["error"] = str(exc)
        output["authenticated"] = auth_result
    elif not password:
        output["authenticated"] = {
            "skipped": True,
            "reason": "set TPLINK_ROUTER_PASSWORD in your shell to run the authenticated probe",
        }

    if args.prometheus:
        auth = output.get("authenticated")
        if not isinstance(auth, dict):
            print("# error: authentication failed", file=sys.stderr)
            return 1
        if auth.get("error"):
            print(f"# error: {auth['error']}", file=sys.stderr)
            return 1
        if auth.get("skipped"):
            print(f"# skipped: {auth['reason']}", file=sys.stderr)
            return 1
        update_metrics(
            device_name(),
            auth.get("metrics", {}),
            client_class=auth.get("client", "unknown"),
        )
        sys.stdout.write(generate_latest().decode())
        return 0

    if args.json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return 0

    print(f"Host: {args.host}")
    print(f"Reachable: {unauth.get('reachable')}")
    if unauth.get("model"):
        print(f"Model: {unauth.get('model')}")
    auth = output.get("authenticated")
    if isinstance(auth, dict) and auth.get("error"):
        print(f"Auth failed: {auth['error']}")
        return 1
    if isinstance(auth, dict) and auth.get("skipped"):
        print(auth["reason"])
        return 0
    if isinstance(auth, dict) and auth.get("client"):
        print(f"Authenticated via {auth['client']} (user={auth.get('username')!r})")
        metrics = auth.get("metrics", {})
        cgi = metrics.get("cgi") or {}
        print(f"CPU: {cgi.get('cpu_percent')}%  Mem: {cgi.get('mem_percent')}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
