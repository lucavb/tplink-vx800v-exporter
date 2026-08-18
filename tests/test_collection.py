from __future__ import annotations

import json
import unittest
from unittest.mock import ANY, Mock, call, patch

from auth import collect_router_metrics
from logging_utils import ProbeLog
from parsers import collect_cgi_metrics
from router import (
    vx_fetch_host_entries,
    vx_fetch_oid_get,
    vx_fetch_wifi_clients,
    vx_ui_request,
)


class FakeActItem:
    GET = "GET"
    GL = "GL"

    def __init__(self, operation, oid, *, stack="0,0,0,0,0,0", attrs):
        self.operation = operation
        self.oid = oid
        self.stack = stack
        self.attrs = attrs


class FakeInner:
    ActItem = FakeActItem

    def __init__(self, values):
        self.values = values
        self.acts = []

    def req_act(self, acts):
        self.acts.extend(acts)
        return 0, self.values


class CollectionTests(unittest.TestCase):
    @patch("auth.vx_clear_busy")
    @patch("auth.collect_wifi_metrics")
    @patch("auth.vx_fetch_host_entries")
    @patch("auth.collect_cgi_metrics")
    @patch("auth.collect_status_overview")
    def test_poll_uses_each_source_once(
        self,
        collect_overview: Mock,
        collect_cgi: Mock,
        fetch_hosts: Mock,
        collect_wifi: Mock,
        clear_busy: Mock,
    ) -> None:
        inner = object()
        client = Mock()
        client._inner = inner
        client.get_firmware.return_value = {"model": "VX800v"}
        collect_overview.return_value = {"system": {"model": "VX800v"}}
        collect_cgi.return_value = {"cpu_usage": 0.1}
        fetch_hosts.return_value = []
        collect_wifi.return_value = {"clients": []}

        result = collect_router_metrics(client, ProbeLog(False))

        self.assertEqual(result["connected_clients"], [])
        collect_overview.assert_called_once_with(inner, ANY)
        collect_cgi.assert_called_once_with(client, ANY)
        fetch_hosts.assert_called_once_with(inner)
        collect_wifi.assert_called_once_with(inner, ANY, [])
        self.assertEqual(clear_busy.call_count, 2)
        self.assertEqual(
            clear_busy.call_args_list,
            [
                call(inner, is_user_active=True),
                call(inner, is_user_active=None),
            ],
        )
        self.assertFalse(client.get_status.called)
        self.assertFalse(client.get_ipv4_status.called)
        self.assertFalse(client.get_ipv6_status.called)

    @patch("parsers.parse_dsl_stats")
    @patch("parsers.fetch_show_dsl_stats")
    @patch("parsers.parse_cpu_mem_cgi", return_value=(0.1, 0.2))
    def test_dsl_collector_passes_only_response_body_to_parser(
        self,
        _parse_cpu_mem: Mock,
        fetch_dsl: Mock,
        parse_dsl: Mock,
    ) -> None:
        fetch_dsl.return_value = (200, 'var Statistics_buf="Status: Showtime";')
        parse_dsl.return_value = {"status": "Showtime", "link_up": True}
        client = Mock()
        client._inner = object()

        result = collect_cgi_metrics(client, ProbeLog(False))

        parse_dsl.assert_called_once_with('var Statistics_buf="Status: Showtime";')
        self.assertTrue(result["dsl"]["link_up"])

    @patch("router.vx_ui_request", return_value={"upTime": "123"})
    def test_oid_get_tries_empty_attributes_first(self, request: Mock) -> None:
        inner = FakeInner([])

        result = vx_fetch_oid_get(inner, "DEV2_DEV_INFO", attrs=["upTime"])

        self.assertEqual(result, {"upTime": "123"})
        request.assert_called_once_with(
            inner,
            FakeActItem.GET,
            "DEV2_DEV_INFO",
            [],
            stack="0,0,0,0,0,0",
            is_user_active=None,
        )

    @patch("router.vx_ui_request")
    def test_dynamic_lists_use_user_active_request(self, request: Mock) -> None:
        entry = {"MACAddress": "AA:BB:CC:DD:EE:FF"}
        request.return_value = [entry]
        inner = Mock()
        inner.ActItem.GL = "gl"
        inner._to_list.side_effect = lambda value: value if isinstance(value, list) else [value]

        self.assertEqual(vx_fetch_host_entries(inner), [entry])
        self.assertEqual(vx_fetch_wifi_clients(inner, refresh=False), [entry])

        self.assertEqual(request.call_args_list[0].args, (inner, "gl", "DEV2_HOST_ENTRY"))
        self.assertEqual(request.call_args_list[1].args[:3], (inner, "gl", "DEV2_ADT_WIFI_CLIENT"))

    def test_ui_request_matches_browser_transport(self) -> None:
        response = Mock(status_code=200)
        response.iter_content.return_value = [b"encrypted-response"]
        inner = Mock()
        inner.host = "https://192.168.1.1"
        inner.HEADERS = {"User-Agent": "test"}
        inner._token = "token"
        inner.timeout = 60
        inner._verify_ssl = False
        inner._prepare_data.return_value = ("signature", "ciphertext", "tag")
        inner.req.post.return_value = response
        inner._encryption.aes_decrypt.return_value = json.dumps(
            {"success": True, "data": [{"active": "1"}]}
        )

        result = vx_ui_request(inner, "gl", "DEV2_HOST_ENTRY")

        self.assertEqual(result, [{"active": "1"}])
        payload = json.loads(inner._prepare_data.call_args.args[0])
        self.assertTrue(payload["isuseractive"])
        posted_headers = inner.req.post.call_args.kwargs["headers"]
        self.assertEqual(posted_headers["Connection"], "keep-alive")
        self.assertEqual(posted_headers["X-Requested-With"], "XMLHttpRequest")

        vx_ui_request(
            inner,
            "op",
            "ACT_WIFI_UPDATE_ALLASSOC",
            is_user_active=None,
        )
        action_payload = json.loads(inner._prepare_data.call_args.args[0])
        self.assertNotIn("isuseractive", action_payload)


if __name__ == "__main__":
    unittest.main()
