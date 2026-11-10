#!/usr/bin/env python3
"""Build a sing-box config from VLESS share links using a JSONC template."""

import argparse
import base64
import binascii
import json
import re
import secrets
import subprocess
import sys
import tempfile
import unicodedata
import uuid
from itertools import chain
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qsl, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

LIMIT = 4 * 1024 * 1024
TEMPLATE = Path(__file__).with_name("template.jsonc")
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/|[,\[\]{}]|[^"\s/,\[\]{}]+|\S')
MARKER = re.compile(r"(?:/\*+|//)\s*(@ParserSTART|@ParserEND)\s*(?:\*/)?$")
SLOT = "@VLESS@"
PROBE = "__sing_box_converter_marker__"


class ConversionError(Exception):
    """An error whose message is safe to print."""


def strict_json(source):
    def pairs(items):
        result = dict(items)
        if len(result) != len(items):
            raise ConversionError("Template contains a duplicate JSON key.")
        return result

    def reject_constant(_):
        raise ConversionError("Template contains a non-JSON number.")

    tokens = [match.group() for match in TOKEN.finditer(source)
              if not match.group().startswith(("//", "/*"))]
    cleaned = " ".join(token for index, token in enumerate(tokens)
                       if not (token == "," and index and tokens[index - 1] not in ("[", "{", ",")
                               and tokens[index + 1:index + 2] in (["]"], ["}"])))
    try:
        return json.loads(cleaned, object_pairs_hook=pairs, parse_constant=reject_constant)
    except (ValueError, RecursionError):
        raise ConversionError("Invalid JSONC template.") from None


def read_template(source):
    markers = [(MARKER.fullmatch(match.group())[1], match)
               for match in TOKEN.finditer(source) if MARKER.fullmatch(match.group())]
    if [name for name, _ in markers] != ["@ParserSTART", "@ParserEND"]:
        raise ConversionError("Template needs one ordered @ParserSTART/@ParserEND pair.")
    start, end = (match for _, match in markers)
    body = source[start.end():end.start()]
    block = strict_json("[" + body + "]")
    tokens = [match.group() for match in TOKEN.finditer(body)
              if not match.group().startswith(("//", "/*"))]
    separator = "," if tokens[-1:] == [","] else ""
    probe = strict_json(source[:start.start()] + json.dumps({PROBE: True})
                        + separator + source[end.end():])
    config = strict_json(source)
    if not isinstance(config, dict) or not isinstance(probe, dict):
        raise ConversionError("Template must be a JSON object.")
    outbounds = config.get("outbounds")
    located = probe.get("outbounds")
    marker = {PROBE: True}
    if not isinstance(outbounds, list) or not isinstance(located, list) or located.count(marker) != 1:
        raise ConversionError("Parser markers must enclose whole entries in outbounds.")
    index = located.index(marker)
    before, after = located[:index], located[index + 1:]
    if before + block + after != outbounds:
        raise ConversionError("Parser markers must enclose whole entries in outbounds.")
    return config, before, block, after


def decode_base64(value):
    raw = value.encode("ascii")
    if b"=" not in raw:
        raw += b"=" * (-len(raw) % 4)
    return base64.b64decode(raw, altchars=b"-_", validate=True)


def subscription_lines(data):
    try:
        source = data.decode("utf-8-sig").strip()
        if not re.search(r"(?im)^\s*[a-z][a-z0-9+.-]*://", source):
            source = decode_base64("".join(source.split())).decode("utf-8-sig")
    except (UnicodeError, ValueError, binascii.Error):
        raise ConversionError("Expected a plain-text or Base64 subscription.") from None
    return [line.strip() for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def checked_url(value, allow_http):
    try:
        url = urlsplit(value)
        if (url.scheme in ({"https", "http"} if allow_http else {"https"})
                and url.hostname and url.username is None and url.password is None
                and not url.fragment and not any(ord(c) < 33 or ord(c) == 127 for c in value)):
            return
    except ValueError:
        pass
    raise ConversionError("Invalid subscription URL. HTTPS is required unless --allow-http is set.")


class SubscriptionRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl, False)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_limited(stream):
    data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ConversionError("Input exceeds the 4 MiB limit.")
    return data


def fetch_subscription(url, allow_http):
    checked_url(url, allow_http)
    request = Request(url, headers={"Accept": "text/plain", "User-Agent": "sing-box-converter/1"})
    try:
        with build_opener(SubscriptionRedirect()).open(request, timeout=15) as response:
            return read_limited(response)
    except HTTPError as error:
        error.close()
        raise ConversionError(f"Subscription download failed (HTTP {error.code}).") from None
    except (OSError, ValueError):
        raise ConversionError("Subscription download failed.") from None


def parse_vless(uri):
    try:
        if re.search(r"%(?![0-9a-fA-F]{2})", uri) or any(ord(c) < 32 for c in uri):
            raise ValueError
        url = urlsplit(uri)
        if (url.scheme != "vless" or url.password is not None or url.path not in ("", "/")
                or not url.hostname or not url.port or not url.username
                or re.search(r"[\s%/\\@]", url.hostname)):
            raise ValueError
        server = url.hostname.encode("idna").decode("ascii")
        port = url.port
        account = str(uuid.UUID(unquote(url.username, errors="strict")))
        pairs = parse_qsl(url.query, keep_blank_values=True, errors="strict", max_num_fields=100)
        params = dict(pairs)
        if any(ord(c) < 32 or ord(c) == 127 for key, value in pairs for c in key + value):
            raise ValueError
        label = unquote(url.fragment, errors="strict")
    except (ValueError, UnicodeError):
        raise ConversionError("Invalid VLESS URI, UUID, host, port or escaping.") from None
    if len(params) != len(pairs):
        raise ConversionError("VLESS query contains a duplicate parameter.")
    if params.get("encryption", "none") not in ("", "none"):
        raise ConversionError("Unsupported VLESS encryption.")
    if any(params.get(key) for key in ("pqv", "mldsa65Verify", "testseed", "ech", "pcs", "cs",
                                       "pinSHA256", "vcn", "fm")):
        raise ConversionError("Unsupported VLESS verification, TLS or masking options.")
    flow = params.get("flow", "")
    transport = params.get("type") or "tcp"
    security = params.get("security") or "none"
    if flow not in ("", "xtls-rprx-vision"):
        raise ConversionError("Unsupported VLESS flow.")
    if flow and (transport not in ("raw", "tcp") or security not in ("tls", "reality")):
        raise ConversionError("Vision requires raw TCP with TLS or REALITY.")
    node = {"type": "vless", "server": server, "server_port": port, "uuid": account}
    if flow:
        node["flow"] = flow
    add_tls(node, params, security)
    add_transport(node, params, transport)
    label = "".join(c for c in label if not unicodedata.category(c).startswith("C")).strip()[:80]
    return label or "VLESS", node


def add_tls(node, params, security):
    if security not in ("none", "tls", "reality"):
        raise ConversionError("Unsupported VLESS security mode.")
    if params.get("allowInsecure", "").lower() not in ("", "0", "false"):
        raise ConversionError("TLS certificate verification cannot be disabled by a link.")
    if security == "none":
        return
    tls = {"enabled": True}
    if params.get("sni"):
        tls["server_name"] = params["sni"]
    if params.get("alpn"):
        tls["alpn"] = [part.strip() for part in params["alpn"].split(",") if part.strip()]
    if params.get("fp") or security == "reality":
        fingerprint = params.get("fp") or "chrome"
        if fingerprint not in {"chrome", "firefox", "edge", "safari", "360", "qq",
                               "ios", "android", "random", "randomized"}:
            raise ConversionError("Unsupported uTLS fingerprint.")
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        key, short_id = params.get("pbk", ""), params.get("sid", "")
        try:
            decoded = decode_base64(key)
        except (UnicodeError, ValueError, binascii.Error):
            raise ConversionError("Invalid REALITY public key.") from None
        if len(decoded) != 32:
            raise ConversionError("REALITY requires a 32-byte public key.")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
            raise ConversionError("Invalid REALITY short ID.")
        if not params.get("sni"):
            raise ConversionError("REALITY requires SNI.")
        tls["reality"] = {
            "enabled": True,
            "public_key": base64.urlsafe_b64encode(decoded).decode().rstrip("="),
            "short_id": short_id.lower(),
        }
    node["tls"] = tls


def add_transport(node, params, transport):
    if transport in ("tcp", "raw"):
        if params.get("headerType", "") not in ("", "none"):
            raise ConversionError("Unsupported TCP header mode.")
        return
    if transport not in ("ws", "grpc", "http", "h2", "httpupgrade"):
        raise ConversionError("Unsupported VLESS transport.")
    if transport == "grpc":
        if params.get("mode") not in (None, "", "gun") or params.get("multiMode") not in (None, "", "false", "0") or params.get("authority"):
            raise ConversionError("Unsupported gRPC mode or authority.")
        node["transport"] = {"type": "grpc", "service_name": params.get("serviceName", "")}
        return
    options = {"type": "http" if transport == "h2" else transport,
               "path": params.get("path") or "/"}
    host = params.get("host")
    if host:
        if options["type"] == "http":
            options["host"] = [part.strip() for part in host.split(",") if part.strip()]
        elif transport == "httpupgrade":
            options["host"] = host
        else:
            options["headers"] = {"Host": host}
    if transport == "ws" and "?ed=" in options["path"]:
        path, early_data = options["path"].rsplit("?ed=", 1)
        if not re.fullmatch(r"[0-9]{1,5}", early_data) or int(early_data) > 65535:
            raise ConversionError("Invalid WebSocket early data size.")
        options.update(path=path or "/", max_early_data=int(early_data),
                       early_data_header_name="Sec-WebSocket-Protocol")
    node["transport"] = options


def build_config(template, links):
    config, before, block, after = read_template(template)
    endpoints = config.get("endpoints", [])
    if not isinstance(endpoints, list):
        raise ConversionError("Template endpoints must be an array.")
    reserved, old_nodes = set(), {SLOT}
    for item, dynamic in chain(((item, True) for item in block),
                               ((item, False) for item in before + after + endpoints)):
        if not isinstance(item, dict) or not isinstance(item.get("tag"), str) or not item["tag"]:
            raise ConversionError("Each template outbound or endpoint needs a tag.")
        tag = item["tag"]
        if tag in reserved or tag in old_nodes:
            raise ConversionError("Template contains duplicate or reserved tags.")
        if dynamic and item.get("type") == "vless":
            old_nodes.add(tag)
        else:
            reserved.add(tag)

    nodes, tags, seen = [], [], set()
    used = reserved | old_nodes
    for location, link in links:
        try:
            label, node = parse_vless(link)
        except ConversionError as error:
            raise ConversionError(f"{location}: {error}") from None
        identity = json.dumps(node, sort_keys=True)
        if identity in seen:
            continue
        seen.add(identity)
        tag, suffix = label, 2
        while tag in used:
            tag = f"{label} ({suffix})"
            suffix += 1
        used.add(tag)
        tags.append(tag)
        nodes.append({"tag": tag, **node})
    if not nodes:
        raise ConversionError("No VLESS nodes found.")

    valid_tags = reserved | set(tags)
    groups = []
    for item in block:
        kind = item.get("type")
        if kind == "vless":
            continue
        if kind not in ("urltest", "selector"):
            raise ConversionError("Parser region supports VLESS, selector and urltest entries.")
        members = item.get("outbounds")
        if not isinstance(members, list) or not all(isinstance(tag, str) for tag in members):
            raise ConversionError("Template group outbounds must be an array of tags.")
        expanded = [node_tag for member in members
                    for node_tag in (tags if member in old_nodes else [member])]
        group = {**item, "outbounds": list(dict.fromkeys(expanded))}
        if not expanded or item["tag"] in expanded or not set(expanded) <= valid_tags:
            raise ConversionError("Template group contains an invalid outbound reference.")
        if kind == "selector" and "default" in item:
            default = item["default"]
            if not isinstance(default, str):
                raise ConversionError("Template selector default must be a tag.")
            group["default"] = tags[0] if default in old_nodes else default
            if group["default"] not in expanded:
                raise ConversionError("Template selector default must be a group member.")
        groups.append(group)

    config["outbounds"] = before + nodes + groups + after
    clash = config.get("experimental", {})
    clash = clash.get("clash_api", {}) if isinstance(clash, dict) else {}
    if isinstance(clash, dict) and clash.get("external_controller") and not clash.get("secret"):
        clash["secret"] = secrets.token_urlsafe(24)
    return config, len(nodes)


def write_config(config, destination, checker):
    # Stage in the destination directory so the final replacement is atomic.
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".sing-box-",
                                     suffix=".json", dir=destination.parent, delete=False) as stream:
        staged = Path(stream.name)
    try:
        with staged.open("w", encoding="utf-8") as stream:
            json.dump(config, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
        if checker:
            try:
                result = subprocess.run([checker, "check", "-c", str(staged.absolute())],
                                        cwd=destination.parent, timeout=30,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.TimeoutExpired):
                raise ConversionError("Could not run sing-box check.") from None
            if result.returncode:
                raise ConversionError("sing-box check rejected the configuration.") from None
        staged.replace(destination)
    finally:
        staged.unlink(missing_ok=True)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default message can contain entire secret-bearing arguments.
        super().error("Invalid or missing arguments. Run with --help.")


def load_input(name):
    if name == "-":
        return read_limited(sys.stdin.buffer)
    with Path(name).open("rb") as stream:
        return read_limited(stream)


def main(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--template", type=Path, default=TEMPLATE, help="JSONC template")
    parser.add_argument("-o", "--output", type=Path, required=True, help="destination JSON file")
    parser.add_argument("--vless", action="append", default=[], metavar="URI", help="VLESS link (repeatable)")
    parser.add_argument("--subscription", action="append", default=[], metavar="URL", help="3x-ui URL (repeatable)")
    parser.add_argument("--subscription-url-file", action="append", default=[], metavar="FILE",
                        help="read one subscription URL from FILE or stdin (-)")
    parser.add_argument("--input", action="append", default=[], metavar="FILE",
                        help="read URI list or Base64 subscription from FILE or stdin (-)")
    parser.add_argument("--allow-http", action="store_true", help="allow a direct HTTP subscription URL")
    parser.add_argument("--check", metavar="SING_BOX", help="run sing-box check before replacing output")
    args = parser.parse_args(argv)
    sources = args.input + args.subscription_url_file
    if not (args.vless or args.subscription or sources) or sources.count("-") > 1:
        parser.error("")
    try:
        destination = args.output.absolute()
        input_paths = [args.template, *(Path(name) for name in sources if name != "-")]
        if any(destination.resolve() == path.resolve() for path in input_paths):
            raise ConversionError("Output must differ from template and input files.")
        template = load_input(str(args.template)).decode("utf-8-sig")
        links = [(f"VLESS argument {i}", link.strip()) for i, link in enumerate(args.vless, 1)]
        payloads = (load_input(name) for name in args.input)
        url_files = (load_input(name).decode("utf-8-sig").strip()
                     for name in args.subscription_url_file)
        subscriptions = (fetch_subscription(url, args.allow_http)
                         for url in (*args.subscription, *url_files))
        skipped = 0
        for source, data in enumerate(chain(payloads, subscriptions), 1):
            for entry, link in enumerate(subscription_lines(data), 1):
                if not link.lower().startswith("vless:"):
                    skipped += 1
                    continue
                links.append((f"Input {source}, entry {entry}", link))
        config, count = build_config(template, links)
        checker = args.check
        if checker and "/" in checker:
            checker = str(Path(checker).absolute())
        write_config(config, destination, checker)
    except ConversionError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError, ValueError, RuntimeError):
        print("Error: could not read inputs or write the configuration.", file=sys.stderr)
        return 1
    print(f"Saved configuration with {count} VLESS node(s).", file=sys.stderr)
    if skipped:
        print(f"Skipped {skipped} non-VLESS subscription entries.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
