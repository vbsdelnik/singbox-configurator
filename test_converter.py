import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request

import converter

ROOT = Path(__file__).resolve().parent
TEMPLATE = converter.TEMPLATE.read_text(encoding="utf-8")
REALITY = (
    "vless://11111111-1111-4111-8111-111111111111@192.0.2.10:443"
    "?type=tcp&encryption=none&security=reality&flow=xtls-rprx-vision"
    "&sni=example.com&fp=chrome&pbk=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
    "&sid=0123456789abcdef&spx=%2F#Demo%20REALITY"
)
WS = (
    "vless://22222222-2222-4222-8222-222222222222@192.0.2.20:443"
    "?type=ws&security=tls&sni=example.org&host=example.org&path=%2Fdemo#Demo%20WebSocket"
)
PAYLOAD = ("\n".join((REALITY, WS)) + "\n").encode("utf-8")


class ConverterTests(unittest.TestCase):
    def test_subscription_formats(self):
        for body in (PAYLOAD, b"\xef\xbb\xbf" + PAYLOAD.replace(b"\n", b"\r\n"),
                     base64.b64encode(PAYLOAD),
                     b" \n" + base64.urlsafe_b64encode(PAYLOAD).rstrip(b"=")):
            with self.subTest(size=len(body)):
                self.assertEqual(converter.subscription_lines(body), [REALITY, WS])
        with self.assertRaises(converter.ConversionError):
            converter.subscription_lines(b"<html>no subscription</html>")

    def test_reality_and_websocket(self):
        name, node = converter.parse_vless(REALITY)
        self.assertEqual(name, "Demo REALITY")
        self.assertEqual(node["flow"], "xtls-rprx-vision")
        self.assertEqual(node["tls"]["server_name"], "example.com")
        self.assertEqual(node["tls"]["utls"]["fingerprint"], "chrome")
        self.assertEqual(node["tls"]["reality"]["short_id"], "0123456789abcdef")
        self.assertEqual(len(converter.decode_base64(node["tls"]["reality"]["public_key"])), 32)
        _, node = converter.parse_vless(WS.replace("%2Fdemo", "%2Fdemo%3Fed%3D2048"))
        self.assertEqual(node["transport"], {"type": "ws", "headers": {"Host": "example.org"},
                                             "path": "/demo", "max_early_data": 2048,
                                             "early_data_header_name": "Sec-WebSocket-Protocol"})

    def test_ipv6_and_grpc(self):
        uri = ("vless://11111111-1111-4111-8111-111111111111@[2001:db8::1]:443"
               "?type=grpc&serviceName=a%2Fb&mode=gun&security=tls&alpn=h2#IPv6")
        _, node = converter.parse_vless(uri)
        self.assertEqual(node["server"], "2001:db8::1")
        self.assertEqual(node["transport"], {"type": "grpc", "service_name": "a/b"})
        self.assertEqual(node["tls"]["alpn"], ["h2"])

    def test_invalid_links_have_safe_errors(self):
        for uri in (REALITY.replace("pbk=BwcH", "pbk=!"),
                    REALITY.replace("sid=0123456789abcdef", "sid=abc"),
                    REALITY.replace("sni=example.com", "sni="),
                    REALITY.replace("type=tcp", "type=xhttp"),
                    WS.replace(":443", ":99999"),
                    WS.replace("type=ws", "type=ws&security=tls"),
                    WS.replace("type=ws", "type=ws&allowInsecure=1"),
                    WS.replace("type=ws", "type=ws&host=%0a")):
            with self.subTest(uri=uri):
                with self.assertRaises(converter.ConversionError) as error:
                    converter.parse_vless(uri)
                self.assertNotIn("11111111-1111", str(error.exception))
                self.assertNotIn("22222222-2222", str(error.exception))

    def test_jsonc_marker_scope_and_literals(self):
        self.assertEqual(converter.strict_json('{"key":"https://example.org/*x*/", // hi\n}'),
                         {"key": "https://example.org/*x*/"})
        for malformed in ('{"x": 1, "x": 2}', '[,]', '[1,,]', '{"x": NaN}'):
            with self.subTest(malformed=malformed), self.assertRaises(converter.ConversionError):
                converter.strict_json(malformed)
        moved = TEMPLATE.replace("@ParserSTART */", "@Elsewhere */")
        with self.assertRaises(converter.ConversionError):
            converter.read_template(moved)
        moved = '{"outbounds": [], "x": [/* @ParserSTART */ {}, /* @ParserEND */]}'
        with self.assertRaises(converter.ConversionError):
            converter.read_template(moved)

    def test_groups_and_routing(self):
        links = [("first", REALITY.split("#")[0] + "#direct-out"),
                 ("second", WS.split("#")[0] + "#direct-out"), ("duplicate", REALITY)]
        config, count = converter.build_config(TEMPLATE, links)
        original = converter.strict_json(TEMPLATE)
        for key in ("dns", "route", "inbounds", "endpoints", "log"):
            self.assertEqual(config[key], original[key])
        self.assertEqual(count, 2)
        out = {item["tag"]: item for item in config["outbounds"]}
        tags = ["direct-out (2)", "direct-out (3)"]
        self.assertEqual(out["auto-proxy-out"]["outbounds"], tags)
        self.assertEqual(out["auto-proxy-out"]["tolerance"], 100)
        self.assertEqual(out["proxy-out"]["outbounds"], ["direct-out", "auto-proxy-out", *tags])
        self.assertEqual(out["proxy-out"]["default"], "auto-proxy-out")
        self.assertEqual(out["ru VPN 🇷🇺"]["outbounds"], ["direct-out"])
        self.assertEqual(out["vpn ①"]["outbounds"], ["direct-out", "proxy-out", *tags])
        self.assertEqual(out["vpn ②"]["default"], "proxy-out")
        self.assertTrue(config["experimental"]["clash_api"]["secret"])
        self.assertNotIn("@VLESS@", json.dumps(config))

    def test_original_style_template(self):
        source = TEMPLATE.replace("@VLESS@", "old-node").replace(
            "/** @ParserSTART */", '/** @ParserSTART */ {"tag":"old-node","type":"vless"},')
        config, _ = converter.build_config(source, [("first", REALITY)])
        groups = {item["tag"]: item for item in config["outbounds"]}
        self.assertNotIn("old-node", groups)
        self.assertEqual(groups["auto-proxy-out"]["outbounds"], ["Demo REALITY"])

    def test_fetch_and_https_policy(self):
        url = "https://example.org/sub/fake-token"
        with patch.object(converter, "build_opener") as opener:
            stream = opener.return_value.open.return_value.__enter__.return_value
            stream.read.return_value = base64.b64encode(PAYLOAD)
            data = converter.fetch_subscription(url, False)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, url)
            self.assertEqual(request.get_header("Accept"), "text/plain")
            self.assertEqual(converter.subscription_lines(data), [REALITY, WS])
        with self.assertRaises(converter.ConversionError):
            converter.checked_url("http://example.org/sub", False)
        converter.checked_url("http://example.org/sub", True)
        with self.assertRaises(converter.ConversionError):
            converter.SubscriptionRedirect().redirect_request(
                Request(url), None, 302, "", {}, "http://example.org/sub")

    def run_cli(self, *args, data=None):
        return subprocess.run([sys.executable, str(ROOT / "converter.py"), *map(str, args)],
                              input=data, capture_output=True, cwd=ROOT, check=False)

    def test_cli_permissions_and_secret_free_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "config.json"
            payload = b"vmess://demo\n" + PAYLOAD
            result = self.run_cli("--input", "-", "-o", output, data=payload)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"Skipped 1", result.stderr)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            original = output.read_bytes()
            self.assertEqual(json.loads(original)["route"]["final"], "proxy-out")
            result = self.run_cli("--vless", "vless://sensitive-token@bad", "-o", output)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b"sensitive-token", result.stderr)
            self.assertEqual(output.read_bytes(), original)
            result = self.run_cli("--unrecognized=sensitive-token")
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"sensitive-token", result.stderr)

    def test_checker_failure_keeps_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "config.json"
            output.write_text("previous")
            with patch.object(converter.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                with self.assertRaisesRegex(converter.ConversionError, "check rejected"):
                    converter.write_config({}, output, "sing-box")
            self.assertEqual(output.read_text(), "previous")
            self.assertEqual(list(output.parent.iterdir()), [output])

    @unittest.skipUnless(os.environ.get("SING_BOX_TEST_BINARY"), "set SING_BOX_TEST_BINARY for integration")
    def test_sing_box_check(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self.run_cli("--input", "-", "-o", Path(folder) / "config.json",
                                  "--check", os.environ["SING_BOX_TEST_BINARY"], data=PAYLOAD)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
