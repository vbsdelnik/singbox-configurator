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

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
TEMPLATE = converter.TEMPLATE.read_text(encoding="utf-8")
PAYLOAD = (TESTS / "demo-vless.txt").read_bytes()
REALITY, WS = PAYLOAD.decode("utf-8").splitlines()
LOCAL_BINARY = TESTS / ("sing-box.exe" if os.name == "nt" else "sing-box")
TEST_BINARY = os.environ.get("SING_BOX_TEST_BINARY") or (
    str(LOCAL_BINARY) if LOCAL_BINARY.is_file() else None
)


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

    def run_cli(self, *args, data=None, cwd=ROOT):
        return subprocess.run([sys.executable, str(ROOT / "converter.py"), *map(str, args)],
                              input=data, capture_output=True, cwd=cwd, check=False)

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

    def test_single_file_uses_automatic_output_name(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "phone.home.txt"
            source.write_text(REALITY + "\n", encoding="utf-8")
            result = self.run_cli("--input", source, cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = root / "json" / "phone.home.json"
            config = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(config["outbounds"][0]["tag"], "Demo REALITY")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_directory_keeps_configs_separate_and_continues_after_invalid_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sources = root / "vless-links"
            sources.mkdir()
            (sources / ".ignore").write_text("ignored", encoding="utf-8")
            (sources / "nested").mkdir()
            (sources / "phone.txt").write_text(REALITY, encoding="utf-8")
            (sources / "tablet").write_text(WS, encoding="utf-8")
            (sources / "broken.txt").write_bytes(PAYLOAD)
            output = root / "json"
            output.mkdir()
            (output / "broken.json").write_text("previous", encoding="utf-8")
            result = self.run_cli("--input", sources, cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"Expected exactly one VLESS URI", result.stderr)
            self.assertEqual(sorted(path.name for path in output.iterdir()),
                             ["broken.json", "phone.json", "tablet.json"])
            self.assertEqual((output / "broken.json").read_text(encoding="utf-8"), "previous")
            for name, expected in (("phone.json", "Demo REALITY"), ("tablet.json", "Demo WebSocket")):
                config = json.loads((output / name).read_text(encoding="utf-8"))
                self.assertEqual([item["tag"] for item in config["outbounds"] if item["type"] == "vless"],
                                 [expected])

    def test_directory_rejects_duplicate_output_names_before_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "phone.txt").write_text(REALITY, encoding="utf-8")
            (root / "Phone.uri").write_text(WS, encoding="utf-8")
            result = self.run_cli("--input", root, cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"same output filename", result.stderr)
            self.assertFalse((root / "json").exists())

    def test_checker_failure_keeps_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "config.json"
            output.write_text("previous")
            with patch.object(converter.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                with self.assertRaisesRegex(converter.ConversionError, "check rejected"):
                    converter.save_or_check_config({}, output, "sing-box")
            self.assertEqual(output.read_text(), "previous")
            self.assertEqual(list(output.parent.iterdir()), [output])

    @unittest.skipUnless(TEST_BINARY, "place sing-box in tests/ or set SING_BOX_TEST_BINARY")
    def test_sing_box_check(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "config.json"
            for previous in (None, "previous"):
                if previous:
                    output.write_text(previous, encoding="utf-8")
                result = self.run_cli("--input", "-", "-o", output,
                                      "--check", TEST_BINARY, data=PAYLOAD)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b"1 of 1 configuration(s) passed", result.stderr)
                self.assertIn(b"without --check", result.stderr)
                if previous:
                    self.assertEqual(output.read_text(encoding="utf-8"), previous)
                else:
                    self.assertFalse(output.exists())

            links = root / "vless-links"
            links.mkdir()
            (links / "reality.txt").write_text(REALITY, encoding="utf-8")
            (links / "websocket.txt").write_text(WS, encoding="utf-8")
            result = self.run_cli("--input", links, "--check", TEST_BINARY, cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"2 of 2 configuration(s) passed", result.stderr)
            self.assertFalse((root / "json").exists())

            (links / "broken.txt").write_text("invalid", encoding="utf-8")
            result = self.run_cli("--input", links, "--check", TEST_BINARY, cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"2 of 3 configuration(s) passed", result.stderr)
            self.assertNotIn(b"without --check", result.stderr)
            self.assertFalse((root / "json").exists())


if __name__ == "__main__":
    unittest.main()
