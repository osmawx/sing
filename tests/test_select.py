"""Unit tests for share/select.py: link parsing and sing-box config generation."""

import base64
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SELECT_PATH = Path(__file__).resolve().parent.parent / "share" / "select.py"


def load_select_module():
    """Load share/select.py under another name: «select» would shadow the stdlib module."""
    spec = importlib.util.spec_from_file_location("sing_select", SELECT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sing_select = load_select_module()


class DecodeBase64Test(unittest.TestCase):
    """decode_base64 accepts standard and url-safe input without padding."""

    def test_decodes_unpadded_standard_base64(self):
        encoded = base64.b64encode(b"hello world").decode().rstrip("=")
        self.assertEqual(sing_select.decode_base64(encoded), "hello world")

    def test_decodes_url_safe_base64(self):
        # b"??>" encodes to "Pz8-" in url-safe form and to "Pz8+" in the standard one
        self.assertEqual(sing_select.decode_base64(b"Pz8-"), "??>")


class LinkNameTest(unittest.TestCase):
    """link_name and set_link_name read and replace server names."""

    def test_reads_fragment_name(self):
        self.assertEqual(sing_select.link_name("trojan://pass@host.example:443#Amsterdam%201"), "Amsterdam 1")

    def test_falls_back_to_host_without_fragment(self):
        self.assertEqual(sing_select.link_name("socks5://user:pass@1.2.3.4:1080"), "1.2.3.4:1080")

    def test_reads_vmess_ps_field(self):
        payload = base64.b64encode(json.dumps({"ps": "Vmess-Node"}).encode()).decode()
        self.assertEqual(sing_select.link_name("vmess://" + payload), "Vmess-Node")

    def test_set_link_name_replaces_fragment(self):
        renamed = sing_select.set_link_name("trojan://pass@host.example:443#old", "New Name")
        self.assertEqual(sing_select.link_name(renamed), "New Name")


class BuildOutboundTest(unittest.TestCase):
    """build_outbound converts every supported scheme into a sing-box outbound or endpoint."""

    def test_vless_reality(self):
        outbound = sing_select.build_outbound(
            "vless://uuid-1@host.example:8443?security=reality&pbk=KEY&sid=ab&fp=firefox&flow=xtls-rprx-vision#n"
        )
        self.assertEqual(outbound["tag"], "proxy")
        self.assertEqual(outbound["uuid"], "uuid-1")
        self.assertEqual(outbound["server_port"], 8443)
        self.assertEqual(outbound["tls"]["reality"]["public_key"], "KEY")
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "firefox")

    def test_trojan_defaults_to_tls_and_ws_transport(self):
        outbound = sing_select.build_outbound("trojan://secret@host.example?type=ws&path=/ws&host=cdn.example#t")
        self.assertEqual(outbound["password"], "secret")
        self.assertEqual(outbound["server_port"], 443)
        self.assertTrue(outbound["tls"]["enabled"])
        self.assertEqual(outbound["transport"], {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example"}})

    def test_vmess(self):
        payload = {"add": "host.example", "port": "443", "id": "uuid-2", "net": "grpc", "tls": "tls", "ps": "v"}
        link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
        outbound = sing_select.build_outbound(link)
        self.assertEqual(outbound["type"], "vmess")
        self.assertEqual(outbound["transport"]["type"], "grpc")
        self.assertEqual(outbound["tls"]["server_name"], "host.example")

    def test_shadowsocks_sip002(self):
        userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:pa:ss").decode().rstrip("=")
        outbound = sing_select.build_outbound(f"ss://{userinfo}@1.2.3.4:8388#ss")
        self.assertEqual((outbound["method"], outbound["password"]), ("aes-256-gcm", "pa:ss"))

    def test_shadowsocks_legacy_base64(self):
        body = base64.b64encode(b"chacha20-ietf-poly1305:pw@1.2.3.4:8388").decode()
        outbound = sing_select.build_outbound(f"ss://{body}#legacy")
        self.assertEqual(outbound["server"], "1.2.3.4")
        self.assertEqual(outbound["server_port"], 8388)

    def test_hysteria2_with_obfs(self):
        outbound = sing_select.build_outbound("hy2://pw@host.example:4433?obfs=salamander&obfs-password=x#h")
        self.assertEqual(outbound["type"], "hysteria2")
        self.assertEqual(outbound["obfs"], {"type": "salamander", "password": "x"})

    def test_wireguard_adds_host_mask(self):
        outbound = sing_select.build_outbound(
            "wireguard://PRIV@1.2.3.4:51820?publickey=PUB&address=10.0.0.2,fd00::2&reserved=1,2,3#wg"
        )
        self.assertEqual(outbound["type"], "wireguard")
        self.assertEqual(outbound["address"], ["10.0.0.2/32", "fd00::2/128"])
        self.assertEqual(outbound["peers"][0]["reserved"], [1, 2, 3])

    def test_amneziawg_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "AmneziaWG"):
            sing_select.build_outbound("wg://PRIV@1.2.3.4:51820?publickey=PUB&address=10.0.0.2&jc=4")

    def test_https_proxy_with_credentials(self):
        outbound = sing_select.build_outbound("https://user:p%40ss@proxy.example#p")
        self.assertEqual(outbound["type"], "http")
        self.assertEqual(outbound["server_port"], 443)
        self.assertEqual(outbound["password"], "p@ss")
        self.assertTrue(outbound["tls"]["enabled"])

    def test_unsupported_scheme(self):
        with self.assertRaisesRegex(ValueError, "не поддерживается"):
            sing_select.build_outbound("openvpn://host.example")

    def test_xhttp_transport_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "xhttp"):
            sing_select.build_outbound("vless://uuid@host.example:443?type=xhttp#x")

    def test_missing_server(self):
        with self.assertRaisesRegex(ValueError, "адреса сервера"):
            sing_select.build_outbound("socks5://")


class WireguardConfTest(unittest.TestCase):
    """wireguard_conf_to_link turns a .conf file into a working wireguard:// link."""

    CONF_TEXT = """
[Interface]
PrivateKey = PRIV/KEY+=
Address = 10.0.0.2/32, fd00::2/128
MTU = 1280
DNS = 1.1.1.1

[Peer]
PublicKey = PUBKEY=
Endpoint = 1.2.3.4:51820
PersistentKeepalive = 25

[Peer]
PublicKey = SECOND=
Endpoint = 5.6.7.8:51820
"""

    def test_round_trips_to_endpoint(self):
        link = sing_select.wireguard_conf_to_link(self.CONF_TEXT, "home")
        endpoint = sing_select.build_outbound(link)
        self.assertEqual(endpoint["private_key"], "PRIV/KEY+=")
        self.assertEqual(endpoint["mtu"], 1280)
        self.assertEqual(endpoint["peers"][0]["public_key"], "PUBKEY=")
        self.assertEqual(endpoint["peers"][0]["persistent_keepalive_interval"], 25)
        self.assertEqual(sing_select.link_name(link), "home")

    def test_requires_keys_and_endpoint(self):
        with self.assertRaises(ValueError):
            sing_select.wireguard_conf_to_link("[Interface]\nPrivateKey = X\n", "broken")


class AddArgumentsTest(unittest.TestCase):
    """parse_links_to_add understands links, plain tokens and the colon format."""

    def test_plain_tokens_with_credentials_and_name(self):
        parsed = sing_select.parse_links_to_add(["socks5", "1.2.3.4:1080", "user", "p@ss", "My", "Proxy"])
        self.assertEqual(parsed, [("socks5://user:p%40ss@1.2.3.4:1080", "My Proxy")])

    def test_colon_link_is_normalized(self):
        parsed = sing_select.parse_links_to_add(["socks5://1.2.3.4:1080:user:pa:ss"])
        self.assertEqual(parsed, [("socks5://user:pa%3Ass@1.2.3.4:1080", "")])

    def test_several_links_in_one_argument(self):
        parsed = sing_select.parse_links_to_add(["trojan://a@h1.example#one\ntrojan://b@h2.example#two"])
        self.assertEqual([link for link, _ in parsed], ["trojan://a@h1.example#one", "trojan://b@h2.example#two"])

    def test_name_with_several_links_exits(self):
        with self.assertRaises(SystemExit):
            sing_select.parse_links_to_add(["trojan://a@h1.example\ntrojan://b@h2.example", "name"])


class FindLinkTest(unittest.TestCase):
    """find_link prefers an exact name over a substring match."""

    LINKS = ["trojan://a@h.example#Amsterdam 2", "trojan://b@h.example#Amsterdam"]

    def test_exact_match_wins(self):
        self.assertEqual(sing_select.find_link(self.LINKS, "amsterdam"), self.LINKS[1])

    def test_substring_match(self):
        self.assertEqual(sing_select.find_link(self.LINKS, "dam 2"), self.LINKS[0])

    def test_no_match(self):
        self.assertIsNone(sing_select.find_link(self.LINKS, "Berlin"))


class IsolatedConfigTestCase(unittest.TestCase):
    """Base case that points every config path of select.py into a temporary directory."""

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        config_dir = Path(self.temporary_directory.name)
        patched_paths = {
            "SUBSCRIPTION_FILE": config_dir / "sing.sub",
            "CUSTOM_PROXIES_FILE": config_dir / "custom.txt",
            "CURRENT_SELECTION_FILE": config_dir / "sing.current",
            "SING_BOX_CONFIG": config_dir / "sing.json",
        }
        for attribute, path in patched_paths.items():
            patcher = mock.patch.object(sing_select, attribute, str(path))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.config_dir = config_dir


class FilesTest(IsolatedConfigTestCase):
    """File-writing helpers keep secrets private and reject unsafe subscription URLs."""

    def test_write_config_is_private_and_routes_to_proxy(self):
        sing_select.write_config("trojan://secret@host.example#Node")
        config_path = self.config_dir / "sing.json"
        config = json.loads(config_path.read_text())
        self.assertEqual(os.stat(config_path).st_mode & 0o777, 0o600)
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(config["route"]["final"], "proxy")
        self.assertEqual((self.config_dir / "sing.current").read_text(), "Node")

    def test_wireguard_goes_to_endpoints(self):
        sing_select.write_config("wg://PRIV@1.2.3.4:51820?publickey=PUB&address=10.0.0.2#wg")
        config = json.loads((self.config_dir / "sing.json").read_text())
        self.assertNotIn("outbounds", config)
        self.assertEqual(config["endpoints"][0]["type"], "wireguard")

    def test_custom_links_are_private_and_skip_comments(self):
        sing_select.write_custom_links(["trojan://a@h.example#one"])
        custom_path = self.config_dir / "custom.txt"
        self.assertEqual(os.stat(custom_path).st_mode & 0o777, 0o600)
        with custom_path.open("a") as custom_file:
            custom_file.write("# comment\n\n")
        self.assertEqual(sing_select.read_custom_links(), ["trojan://a@h.example#one"])

    def test_subscription_rejects_non_http_url(self):
        (self.config_dir / "sing.sub").write_text("file:///etc/passwd\n")
        with mock.patch.object(sing_select.urllib.request, "urlopen") as urlopen:
            self.assertEqual(sing_select.fetch_subscription_links(), [])
        urlopen.assert_not_called()

    def test_subscription_plain_text_keeps_supported_schemes(self):
        (self.config_dir / "sing.sub").write_text("https://sub.example/token\n")
        body = b"trojan://a@h.example#one\nopenvpn://skip\nvless://u@h.example#two\n"
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = body
        with mock.patch.object(sing_select.urllib.request, "urlopen", return_value=response):
            links = sing_select.fetch_subscription_links()
        self.assertEqual(links, ["trojan://a@h.example#one", "vless://u@h.example#two"])

    def test_subscription_base64(self):
        (self.config_dir / "sing.sub").write_text("https://sub.example/token\n")
        body = base64.b64encode(b"trojan://a@h.example#one\n").rstrip(b"=")
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = body
        with mock.patch.object(sing_select.urllib.request, "urlopen", return_value=response):
            self.assertEqual(sing_select.fetch_subscription_links(), ["trojan://a@h.example#one"])


class CommandsTest(IsolatedConfigTestCase):
    """main() drives add, rm, list and select against an isolated config directory."""

    def run_main(self, *arguments):
        """Run main() with the given argv and return captured stdout."""
        with mock.patch.object(sing_select.sys, "argv", ["select.py", *arguments]), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            sing_select.main()
        return stdout.getvalue()

    def test_add_list_select_remove(self):
        self.assertIn("добавлен: Node", self.run_main("add", "trojan://a@h.example", "Node"))
        self.assertIn("  Node", self.run_main())
        self.assertIn("выбран: Node", self.run_main("node"))
        self.assertIn("* Node", self.run_main())
        self.assertIn("удалён: Node", self.run_main("rm", "Node"))
        self.assertEqual(sing_select.read_custom_links(), [])

    def test_add_duplicate_name_exits(self):
        self.run_main("add", "trojan://a@h.example#Node")
        with self.assertRaises(SystemExit):
            self.run_main("add", "trojan://b@h2.example#Node")

    def test_add_invalid_link_exits(self):
        with self.assertRaises(SystemExit):
            self.run_main("add", "openvpn://h.example")

    def test_add_wireguard_conf_file(self):
        conf_path = self.config_dir / "office.conf"
        conf_path.write_text(WireguardConfTest.CONF_TEXT)
        self.assertIn("добавлен: office", self.run_main("add", str(conf_path)))

    def test_unknown_server_exits(self):
        with self.assertRaises(SystemExit):
            self.run_main("Nowhere")

    def test_rm_unknown_exits(self):
        with self.assertRaises(SystemExit):
            self.run_main("rm", "Nowhere")

    def test_missing_arguments_exit(self):
        for arguments in (["add"], ["rm"]):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                self.run_main(*arguments)


if __name__ == "__main__":
    unittest.main()
