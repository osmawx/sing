#!/usr/bin/env python3 -I
"""Генерирует ~/.config/sing-box/sing.json из подписки (например, BlancVPN) или своих прокси.

Использование:
    Вызывается из sing как «sing select …»:
    sing select                    — список серверов (подписка + свои)
    sing select <подстрока>        — выбрать сервер по названию (например «Амстердам»)
    sing select add <ссылка> [имя] — добавить свой прокси
    sing select add <протокол> <айпи:порт> [логин пароль] [имя] — то же без ссылки
    sing select add socks5://айпи:порт:логин:пароль [имя]
    sing select rm <имя>           — удалить свой прокси
    sing select flag <имя> [страна] — флажок для своего прокси (код страны, например GB; без кода — по IP)
    sing exceptions                — список исключений (домены мимо прокси) и режим «все .ru/.su/.рф»
    sing exceptions add <домен…>   — добавить сайты в исключения (поддомены включены)
    sing exceptions rm <домен…>    — убрать сайты из исключений
    sing exceptions ru on|off      — все сайты .ru, .su и .рф идут мимо прокси
    sing exceptions get-json       — состояние в JSON (для расширения браузера)
    sing exceptions set-json       — заменить состояние JSON-ом из stdin (для расширения)

    sing select add <файл.conf> [имя] — импортировать конфиг WireGuard

Поддерживаемые ссылки: vless://, vmess://, trojan://, ss://, hysteria2:// (hy2://),
wireguard:// (wg://), socks5:// (socks://), http://, https://.
Можно передать несколько ссылок через перевод строки.
Подписка — base64 или обычный текст, по одной ссылке в строке.

URL подписки хранится в ~/.config/sing-box/sing.sub,
свои прокси — в ~/.config/sing-box/custom.txt (по одной ссылке в строке, имя во фрагменте #…).
"""

import base64
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request

CONFIG_DIR = os.path.expanduser("~/.config/sing-box")
SUBSCRIPTION_FILE = os.path.join(CONFIG_DIR, "sing.sub")
CUSTOM_PROXIES_FILE = os.path.join(CONFIG_DIR, "custom.txt")
CURRENT_SELECTION_FILE = os.path.join(CONFIG_DIR, "sing.current")
SING_BOX_CONFIG = os.path.join(CONFIG_DIR, "sing.json")
EXCEPTIONS_FILE = os.path.join(CONFIG_DIR, "exceptions.json")
SOCKS_PORT = 1080
DIRECT_TAG = "direct"
MAX_EXCEPTIONS = 500
# Суффиксы российских зон; .рф дублируется в punycode, потому что браузеры шлют домен в ASCII
RU_DOMAIN_SUFFIXES = ("ru", "su", "рф", "xn--p1ai")
DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+(xn--[a-z0-9-]{2,59}|[a-z]{2,63})$")
PLAIN_PROXY_SCHEMES = ("socks", "socks5", "http", "https")
SUPPORTED_SCHEMES = (
    "vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "wireguard", "wg",
    "socks", "socks5", "http", "https",
)
GEOLOCATION_URL = "https://ipwho.is/{ip}?fields=success,country_code"
GEOLOCATION_TIMEOUT_SECONDS = 5
FLAG_PREFIX_PATTERN = re.compile(r"^[\U0001F1E6-\U0001F1FF]{2}\s*")
COUNTRY_CODE_PATTERN = re.compile(r"^[A-Za-z]{2}$")
WIREGUARD_SCHEMES = ("wireguard", "wg")
# Поля AmneziaWG: sing-box их не поддерживает, такой конфиг не заработает
AMNEZIA_FIELDS = ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4")


def decode_base64(text):
    """Декодирует base64 (обычный или url-safe) без обязательного паддинга."""
    if isinstance(text, str):
        text = text.encode()
    text = text.strip()
    padded = text + b"=" * (-len(text) % 4)
    if b"-" in padded or b"_" in padded:
        return base64.urlsafe_b64decode(padded).decode()
    return base64.b64decode(padded).decode()


def fetch_subscription_links():
    """Скачивает подписку и возвращает список ссылок; при ошибке — пустой список."""
    if not os.path.exists(SUBSCRIPTION_FILE):
        return []
    with open(SUBSCRIPTION_FILE) as subscription:
        url = subscription.read().strip()
    # urlopen понимает и file://, поэтому пускаем только http(s)
    if urllib.parse.urlsplit(url).scheme.lower() not in ("http", "https"):
        print("sing: в sing.sub нужен http(s)-URL, показываю только свои", file=sys.stderr)
        return []
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "sing-box"})  # noqa: S310 — схема проверена выше
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            raw = response.read().strip()
    except OSError as error:
        print(f"sing: подписка недоступна ({error}), показываю только свои", file=sys.stderr)
        return []
    # Обычно подписка — base64 без паддинга, но бывает и открытым текстом.
    # b64decode молча выкидывает «://», поэтому открытый текст определяем заранее.
    if b"://" in raw:
        decoded = raw.decode(errors="replace")
    else:
        try:
            decoded = decode_base64(raw)
        except ValueError:
            decoded = ""
    return [
        line.strip() for line in decoded.splitlines()
        if line.split("://", 1)[0].strip().lower() in SUPPORTED_SCHEMES
    ]


def read_custom_links():
    """Читает свои прокси из custom.txt (пустые строки и #-комментарии пропускаются)."""
    if not os.path.exists(CUSTOM_PROXIES_FILE):
        return []
    with open(CUSTOM_PROXIES_FILE) as custom_file:
        return [
            line.strip() for line in custom_file
            if line.strip() and not line.lstrip().startswith("#")
        ]


def write_custom_links(links):
    """Перезаписывает custom.txt с правами 0600 (в ссылках лежат пароли)."""
    file_descriptor = os.open(CUSTOM_PROXIES_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(file_descriptor, "w") as custom_file:
        custom_file.writelines(link + "\n" for link in links)


def link_name(link):
    """Возвращает человекочитаемое название сервера из ссылки."""
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        # vmess:// — base64-JSON, имя в поле ps
        try:
            return json.loads(decode_base64(link[len("vmess://"):].split("#", 1)[0])).get("ps", "")
        except ValueError:
            pass
    name = urllib.parse.unquote(urllib.parse.urlsplit(link).fragment)
    return name or link_endpoint_label(link)


def link_endpoint_label(link):
    """Имя по умолчанию: только host:port, без логина и пароля (формат host:port:login:password тоже)."""
    authority = link.split("://", 1)[-1].split("#")[0].split("?")[0].split("/")[0]
    endpoint = authority.split("@")[-1]
    if endpoint.startswith("["):
        return endpoint
    return ":".join(endpoint.split(":")[:2])


def set_link_name(link, name):
    """Возвращает ссылку с заменённым именем (фрагментом или полем ps у vmess)."""
    if link.lower().startswith("vmess://"):
        payload = json.loads(decode_base64(link[len("vmess://"):].split("#", 1)[0]))
        payload["ps"] = name
        return "vmess://" + base64.b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode()
    return link.split("#", 1)[0] + "#" + urllib.parse.quote(name)


def country_code_to_flag(country_code):
    """Превращает код страны (GB) в эмодзи-флаг; ValueError, если код неверный."""
    if not COUNTRY_CODE_PATTERN.match(country_code):
        raise ValueError(f"код страны из двух букв, например GB (получено «{country_code}»)")
    return "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in country_code.upper())


def strip_flag(name):
    """Убирает флаг в начале имени, если он есть."""
    return FLAG_PREFIX_PATTERN.sub("", name, count=1)


def has_flag(name):
    """Есть ли в начале имени эмодзи-флаг."""
    return bool(FLAG_PREFIX_PATTERN.match(name))


def link_server_host(link):
    """Адрес сервера из ссылки (для определения страны); пустая строка, если не удалось."""
    try:
        outbound = build_outbound(link)
    except (ValueError, KeyError, IndexError):
        return ""
    if outbound.get("type") == "wireguard":
        return outbound["peers"][0].get("address", "")
    return outbound.get("server", "")


def lookup_country_code(server_host):
    """Определяет код страны по IP сервера через ipwho.is; пустая строка при сбое."""
    try:
        server_ip = socket.gethostbyname(server_host)
        request = urllib.request.Request(  # noqa: S310 — схема https зашита в константе
            GEOLOCATION_URL.format(ip=server_ip), headers={"User-Agent": "sing"},
        )
        with urllib.request.urlopen(request, timeout=GEOLOCATION_TIMEOUT_SECONDS) as response:  # noqa: S310
            data = json.load(response)
    except (OSError, ValueError):
        return ""
    return data.get("country_code", "") if data.get("success") else ""


def link_with_flag(link, country_code):
    """Возвращает ссылку, у которой имя начинается с флага страны (старый флаг заменяется)."""
    flag = country_code_to_flag(country_code)
    return set_link_name(link, f"{flag} {strip_flag(link_name(link))}")


def normalize_domain(text):
    """Приводит домен или URL к чистому домену в ASCII; None, если это не домен."""
    candidate = text.strip().lower()
    if "://" in candidate:
        candidate = urllib.parse.urlsplit(candidate).hostname or ""
    candidate = re.sub(r"^\*?\.", "", candidate)
    candidate = re.split(r"[/?#:]", candidate, maxsplit=1)[0].rstrip(".")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return candidate if DOMAIN_PATTERN.match(candidate) else None


def read_exceptions():
    """Читает исключения: {"domains": [...], "bypass_ru": bool}; без файла — пустые."""
    try:
        with open(EXCEPTIONS_FILE) as exceptions_file:
            stored = json.load(exceptions_file)
    except (OSError, ValueError):
        stored = {}
    domains = [d for d in stored.get("domains", []) if isinstance(d, str) and DOMAIN_PATTERN.match(d)]
    return {"domains": domains, "bypass_ru": bool(stored.get("bypass_ru", False))}


def write_exceptions(exceptions):
    """Сохраняет исключения (права 0600, как у остальных файлов sing)."""
    file_descriptor = os.open(EXCEPTIONS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(file_descriptor, "w") as exceptions_file:
        json.dump(exceptions, exceptions_file, ensure_ascii=False, indent=2)


def build_route(final_tag):
    """Строит секцию route: домены из исключений идут в direct, остальное — в прокси."""
    exceptions = read_exceptions()
    suffixes = list(exceptions["domains"])
    if exceptions["bypass_ru"]:
        suffixes.extend(suffix for suffix in RU_DOMAIN_SUFFIXES if suffix not in suffixes)
    route = {"final": final_tag}
    if suffixes:
        route["rules"] = [{"domain_suffix": suffixes, "outbound": DIRECT_TAG}]
    return route


def apply_exceptions_to_config():
    """Обновляет route в готовом sing.json без повторного скачивания подписки."""
    if not os.path.exists(SING_BOX_CONFIG):
        return
    with open(SING_BOX_CONFIG) as config_file:
        config = json.load(config_file)
    final_tag = config.get("route", {}).get("final")
    if not final_tag:
        return
    config["route"] = build_route(final_tag)
    # Конфиг, созданный старой версией sing, не содержит direct: правила на него ссылаются
    outbounds = config.setdefault("outbounds", [])
    if not any(outbound.get("tag") == DIRECT_TAG for outbound in outbounds):
        outbounds.append({"type": "direct", "tag": DIRECT_TAG})
    file_descriptor = os.open(SING_BOX_CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(file_descriptor, "w") as config_file:
        json.dump(config, config_file, ensure_ascii=False, indent=2)


def parse_domains(raw_domains):
    """Нормализует список доменов; при неверном домене завершает работу с понятной ошибкой."""
    domains = []
    for raw_domain in raw_domains:
        domain = normalize_domain(raw_domain)
        if not domain:
            sys.exit(f"sing: «{raw_domain}» не похоже на домен (пример: example.com)")
        if domain not in domains:
            domains.append(domain)
    return domains


def print_exceptions(exceptions):
    """Печатает исключения в человекочитаемом виде."""
    print(f"все .ru/.su/.рф мимо прокси: {'да' if exceptions['bypass_ru'] else 'нет'}")
    for domain in exceptions["domains"]:
        print(f"  {domain}")


def run_exceptions_command(arguments):
    """Подкоманда exceptions: показать, добавить, убрать, переключить .ru, обмен JSON."""
    exceptions = read_exceptions()
    action = arguments[0] if arguments else ""
    if action == "":
        print_exceptions(exceptions)
        return
    if action == "get-json":
        print(json.dumps(exceptions, ensure_ascii=False))
        return
    if action == "add" and len(arguments) > 1:
        merged = exceptions["domains"] + [d for d in parse_domains(arguments[1:]) if d not in exceptions["domains"]]
        exceptions = {**exceptions, "domains": merged}
    elif action in ("rm", "remove") and len(arguments) > 1:
        removed = set(parse_domains(arguments[1:]))
        exceptions = {**exceptions, "domains": [d for d in exceptions["domains"] if d not in removed]}
    elif action == "ru" and len(arguments) == 2 and arguments[1] in ("on", "off"):
        exceptions = {**exceptions, "bypass_ru": arguments[1] == "on"}
    elif action == "set-json":
        try:
            incoming = json.load(sys.stdin)
            exceptions = {"domains": parse_domains(incoming["domains"]), "bypass_ru": bool(incoming["bypass_ru"])}
        except (ValueError, KeyError, TypeError):
            sys.exit('sing: set-json ждёт {"domains": [...], "bypass_ru": true|false}')
    else:
        sys.exit("sing: exceptions [add <домен…> | rm <домен…> | ru on|off | get-json | set-json]")
    if len(exceptions["domains"]) > MAX_EXCEPTIONS:
        sys.exit(f"sing: не больше {MAX_EXCEPTIONS} исключений")
    write_exceptions(exceptions)
    apply_exceptions_to_config()
    print_exceptions(exceptions) if action != "set-json" else print(json.dumps(exceptions, ensure_ascii=False))


def build_tls(params, server_host, security):
    """Собирает блок tls для sing-box из параметров ссылки (tls / reality / none)."""
    if security not in ("tls", "reality", "xtls"):
        return None
    tls = {"enabled": True, "server_name": params.get("sni") or params.get("peer") or server_host}
    if params.get("allowInsecure") in ("1", "true") or params.get("insecure") in ("1", "true"):
        tls["insecure"] = True
    if params.get("alpn"):
        tls["alpn"] = params["alpn"].split(",")
    fingerprint = params.get("fp")
    # Reality в sing-box работает только поверх uTLS
    if fingerprint or security == "reality":
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint or "chrome"}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": params.get("pbk", ""),
            "short_id": params.get("sid", ""),
        }
    return tls


def build_transport(params):
    """Собирает блок transport (ws / grpc / http / httpupgrade); для tcp — None."""
    transport_type = params.get("type") or params.get("net") or "tcp"
    host = params.get("host", "")
    path = params.get("path", "") or "/"
    if transport_type in ("tcp", "raw"):
        return None
    if transport_type == "ws":
        transport = {"type": "ws", "path": path}
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if transport_type == "grpc":
        return {"type": "grpc", "service_name": params.get("serviceName", "")}
    if transport_type in ("http", "h2"):
        transport = {"type": "http", "path": path}
        if host:
            transport["host"] = host.split(",")
        return transport
    if transport_type == "httpupgrade":
        return {"type": "httpupgrade", "host": host, "path": path}
    raise ValueError(f"транспорт «{transport_type}» sing-box не поддерживает")


def build_vless_or_trojan(parts, params, protocol):
    """Преобразует vless:// или trojan:// ссылку в outbound."""
    credential = urllib.parse.unquote(parts.username or "")
    outbound = {"type": protocol, "server": parts.hostname, "server_port": parts.port or 443}
    if protocol == "vless":
        outbound["uuid"] = credential
        if params.get("flow"):
            outbound["flow"] = params["flow"]
        default_security = "none"
    else:
        outbound["password"] = credential
        default_security = "tls"
    tls = build_tls(params, parts.hostname, params.get("security") or default_security)
    if tls:
        outbound["tls"] = tls
    transport = build_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def build_vmess(link):
    """Преобразует vmess:// (base64-JSON формата v2rayN) в outbound."""
    payload = json.loads(decode_base64(link[len("vmess://"):].split("#", 1)[0]))
    params = {key: str(value) for key, value in payload.items()}
    # В v2rayN ws-заголовок/путь лежат в host/path, тип транспорта — в net
    params["type"] = params.get("net", "tcp")
    outbound = {
        "type": "vmess",
        "server": params["add"],
        "server_port": int(params["port"]),
        "uuid": params["id"],
        "alter_id": int(params.get("aid") or 0),
        "security": params.get("scy") or "auto",
    }
    tls = build_tls(params, params["add"], params.get("tls") or "none")
    if tls:
        outbound["tls"] = tls
    transport = build_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def build_shadowsocks(link):
    """Преобразует ss:// (SIP002 или старый base64-формат) в outbound."""
    body = link[len("ss://"):].split("#", 1)[0]
    if "@" not in body:
        # Старый формат: ss://base64(method:password@host:port)
        body = decode_base64(body.split("?", 1)[0])
    parts = urllib.parse.urlsplit("ss://" + body)
    userinfo = urllib.parse.unquote(body.rsplit("@", 1)[0])
    if ":" not in userinfo:
        userinfo = decode_base64(userinfo)
    method, password = userinfo.split(":", 1)
    return {
        "type": "shadowsocks",
        "server": parts.hostname,
        "server_port": parts.port,
        "method": method,
        "password": password,
    }


def build_hysteria2(parts, params):
    """Преобразует hysteria2:// (hy2://) в outbound."""
    outbound = {
        "type": "hysteria2",
        "server": parts.hostname,
        "server_port": parts.port or 443,
        "password": urllib.parse.unquote(parts.username or ""),
        "tls": build_tls(params, parts.hostname, "tls"),
    }
    if params.get("obfs"):
        outbound["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    return outbound


def first_param(params, *names):
    """Возвращает значение первого непустого параметра из списка синонимов."""
    for name in names:
        if params.get(name):
            return params[name]
    return ""


def build_wireguard(parts, params):
    """Преобразует wireguard:// (wg://) в endpoint sing-box.

    Понимает форматы v2rayN (ключ в userinfo, publickey/address) и Hiddify (pk/peer_pk/local_address).
    """
    if any(field in params for field in AMNEZIA_FIELDS):
        raise ValueError("AmneziaWG sing-box не поддерживает")
    private_key = urllib.parse.unquote(parts.username or "") or first_param(params, "privatekey", "pk", "private_key")
    public_key = first_param(params, "publickey", "peer_pk", "public_key", "peer_public_key")
    addresses = first_param(params, "address", "local_address", "ip")
    if not (private_key and public_key and addresses):
        raise ValueError("в WireGuard-ссылке нужны приватный ключ, publickey и address")
    peer = {
        "address": parts.hostname,
        "port": parts.port or 51820,
        "public_key": public_key,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
    }
    pre_shared_key = first_param(params, "presharedkey", "psk", "pre_shared_key")
    if pre_shared_key:
        peer["pre_shared_key"] = pre_shared_key
    if params.get("reserved"):
        peer["reserved"] = [int(byte) for byte in params["reserved"].split(",")]
    if params.get("keepalive"):
        peer["persistent_keepalive_interval"] = int(params["keepalive"])
    endpoint = {
        "type": "wireguard",
        "address": [
            # Адрес без маски — это один хост
            address.strip() if "/" in address else address.strip() + ("/128" if ":" in address else "/32")
            for address in addresses.split(",") if address.strip()
        ],
        "private_key": private_key,
        "peers": [peer],
    }
    if params.get("mtu"):
        endpoint["mtu"] = int(params["mtu"])
    return endpoint


def wireguard_conf_to_link(conf_text, fallback_name):
    """Превращает файл конфигурации WireGuard (.conf) в ссылку wireguard://.

    Берёт секцию [Interface] и первый [Peer]; DNS и AllowedIPs игнорирует —
    sing-box шлёт в туннель только трафик приложений, запущенных через sing.
    """
    sections = {}
    current_section = None
    for raw_line in conf_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip().lower()
            # Нужен только первый [Peer]
            if current_section in sections:
                current_section = None
            else:
                sections[current_section] = {}
            continue
        if current_section and "=" in line:
            key, value = line.split("=", 1)
            sections[current_section][key.strip().lower()] = value.strip()
    interface = sections.get("interface", {})
    peer = sections.get("peer", {})
    if any(field in interface for field in AMNEZIA_FIELDS):
        raise ValueError("AmneziaWG sing-box не поддерживает")
    if not (interface.get("privatekey") and peer.get("publickey") and peer.get("endpoint")):
        raise ValueError("в конфиге нет PrivateKey, PublicKey или Endpoint")
    params = {"publickey": peer["publickey"], "address": interface.get("address", "").replace(" ", "")}
    if peer.get("presharedkey"):
        params["presharedkey"] = peer["presharedkey"]
    if interface.get("mtu"):
        params["mtu"] = interface["mtu"]
    if peer.get("persistentkeepalive"):
        params["keepalive"] = peer["persistentkeepalive"]
    private_key = urllib.parse.quote(interface["privatekey"], safe="")
    query = urllib.parse.urlencode(params)
    return f"wireguard://{private_key}@{peer['endpoint']}?{query}#{urllib.parse.quote(fallback_name)}"


def build_plain_proxy(parts, scheme):
    """Преобразует socks5:// / http:// / https:// в outbound."""
    is_socks = scheme in ("socks", "socks5")
    outbound = {
        "type": "socks" if is_socks else "http",
        "server": parts.hostname,
        "server_port": parts.port or (1080 if is_socks else 443 if scheme == "https" else 8080),
    }
    if is_socks:
        outbound["version"] = "5"
    if parts.username:
        outbound["username"] = urllib.parse.unquote(parts.username)
        outbound["password"] = urllib.parse.unquote(parts.password or "")
    if scheme == "https":
        outbound["tls"] = {"enabled": True, "server_name": parts.hostname}
    return outbound


def build_outbound(link):
    """Преобразует ссылку любого поддерживаемого протокола в outbound sing-box."""
    scheme = link.split("://", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"протокол «{scheme}» не поддерживается")
    if scheme == "vmess":
        outbound = build_vmess(link)
    elif scheme == "ss":
        outbound = build_shadowsocks(link)
    else:
        parts = urllib.parse.urlsplit(link)
        params = dict(urllib.parse.parse_qsl(parts.query))
        if scheme in ("vless", "trojan"):
            outbound = build_vless_or_trojan(parts, params, scheme)
        elif scheme in ("hysteria2", "hy2"):
            outbound = build_hysteria2(parts, params)
        elif scheme in WIREGUARD_SCHEMES:
            outbound = build_wireguard(parts, params)
        else:
            outbound = build_plain_proxy(parts, scheme)
    server = outbound["peers"][0]["address"] if outbound["type"] == "wireguard" else outbound.get("server")
    if not server:
        raise ValueError("в ссылке нет адреса сервера")
    # tag фиксированный — на него ссылается route.final
    return {"tag": "proxy", **outbound}


def write_config(link):
    """Пишет конфиг sing-box с локальным SOCKS5 и выбранным сервером.

    WireGuard в sing-box 1.13+ — это endpoint, а не outbound; get_server_host в sing
    читает адрес из outbounds.0.server или endpoints.0.peers.0.address.
    """
    outbound = build_outbound(link)
    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT}
        ],
    }
    # direct идёт вторым: sing читает адрес сервера из outbounds.0
    direct_outbound = {"type": "direct", "tag": DIRECT_TAG}
    if outbound["type"] == "wireguard":
        config["endpoints"] = [outbound]
        config["outbounds"] = [direct_outbound]
    else:
        config["outbounds"] = [outbound, direct_outbound]
    config["route"] = build_route(outbound["tag"])
    file_descriptor = os.open(SING_BOX_CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(file_descriptor, "w") as config_file:
        json.dump(config, config_file, ensure_ascii=False, indent=2)
    with open(CURRENT_SELECTION_FILE, "w") as current_file:
        current_file.write(link_name(link))


def read_current_name():
    """Возвращает имя текущего выбранного сервера (или пустую строку)."""
    if not os.path.exists(CURRENT_SELECTION_FILE):
        return ""
    with open(CURRENT_SELECTION_FILE) as current_file:
        return current_file.read().strip()


def find_link(links, query):
    """Ищет ссылку по имени: сначала точное совпадение, потом подстрока."""
    lowered_query = query.lower()
    exact_matches = [link for link in links if link_name(link).lower() == lowered_query]
    if exact_matches:
        return exact_matches[0]
    partial_matches = [link for link in links if lowered_query in link_name(link).lower()]
    return partial_matches[0] if partial_matches else None


def plain_tokens_to_link(tokens):
    """Превращает «протокол айпи:порт [логин пароль] [имя…]» в ссылку протокол://логин:пароль@айпи:порт.

    Возвращает (ссылка, имя) или None, если токены не в этом формате.
    """
    if len(tokens) < 2:
        return None
    # Допускаем и «socks5 …», и «socks5:// …»
    scheme = tokens[0].lower().removesuffix("://")
    if scheme not in PLAIN_PROXY_SCHEMES or "://" in tokens[1] or ":" not in tokens[1]:
        return None
    address = tokens[1]
    credentials = ""
    name_tokens = tokens[2:]
    if len(tokens) >= 4:
        login, password = tokens[2], tokens[3]
        credentials = f"{urllib.parse.quote(login, safe='')}:{urllib.parse.quote(password, safe='')}@"
        name_tokens = tokens[4:]
    elif len(tokens) == 3:
        sys.exit("sing: после адреса нужны и логин, и пароль (или ничего)")
    return f"{scheme}://{credentials}{address}", " ".join(name_tokens)


def normalize_colon_link(link):
    """Переписывает протокол://айпи:порт:логин:пароль в протокол://логин:пароль@айпи:порт.

    Остальные ссылки возвращает без изменений.
    """
    scheme, separator, rest = link.partition("://")
    if not separator or scheme.lower() not in PLAIN_PROXY_SCHEMES:
        return link
    address, hash_sign, fragment = rest.partition("#")
    # maxsplit=3 — пароль может содержать двоеточия
    address_parts = address.split(":", 3)
    if len(address_parts) != 4 or not address_parts[1].isdigit() or "@" in address_parts[0]:
        return link
    host, port, login, password = address_parts
    credentials = f"{urllib.parse.quote(login, safe='')}:{urllib.parse.quote(password, safe='')}"
    return f"{scheme}://{credentials}@{host}:{port}{hash_sign}{fragment}"


def parse_links_to_add(arguments):
    """Разбирает аргументы add в список пар (ссылка, имя).

    Понимает ссылки протокол://… (несколько через пробел/перевод строки, имя — последними словами)
    и строки «протокол айпи:порт логин пароль [имя]» (несколько — каждая на своей строке),
    а также протокол://айпи:порт:логин:пароль.
    """
    plain_link = plain_tokens_to_link(arguments)
    if plain_link:
        return [plain_link]
    # Путь к файлу .conf WireGuard
    conf_path = os.path.expanduser(arguments[0])
    if arguments[0].lower().endswith(".conf") and os.path.isfile(conf_path):
        with open(conf_path) as conf_file:
            fallback_name = os.path.splitext(os.path.basename(conf_path))[0]
            try:
                link = wireguard_conf_to_link(conf_file.read(), fallback_name)
            except ValueError as error:
                sys.exit(f"sing: не разобрал {arguments[0]} ({error})")
        return [(link, " ".join(arguments[1:]))]
    first_argument, name = arguments[0], " ".join(arguments[1:])
    parsed_links = []
    for line in first_argument.splitlines():
        tokens = line.split()
        plain_link = plain_tokens_to_link(tokens)
        if plain_link:
            parsed_links.append(plain_link)
        else:
            parsed_links.extend((token, "") for token in tokens if "://" in token)
    if name:
        if len(parsed_links) > 1:
            sys.exit("sing: имя можно задать только при добавлении одной ссылки")
        parsed_links = [(link, name) for link, _ in parsed_links]
    return [(normalize_colon_link(link), link_name_override) for link, link_name_override in parsed_links]


def add_custom_proxies(arguments):
    """Проверяет и добавляет свои прокси в custom.txt."""
    new_links = parse_links_to_add(arguments)
    if not new_links:
        sys.exit("sing: не нашёл ни одного прокси (протокол://… или «протокол айпи:порт логин пароль»)")
    custom_links = read_custom_links()
    existing_names = {link_name(link) for link in custom_links}
    for link, name in new_links:
        if name:
            link = set_link_name(link, name)
        try:
            build_outbound(link)
        except (ValueError, KeyError, IndexError) as error:
            sys.exit(f"sing: не разобрал ссылку ({error})")
        if not has_flag(link_name(link)):
            # Флаг по IP сервера; при сбое сети имя остаётся как есть
            detected_code = lookup_country_code(link_server_host(link))
            if detected_code:
                link = link_with_flag(link, detected_code)
        if link_name(link) in existing_names:
            sys.exit(f"sing: «{link_name(link)}» уже есть — задай другое имя")
        custom_links.append(link)
        existing_names.add(link_name(link))
        print(f"добавлен: {link_name(link)}")
    write_custom_links(custom_links)
    print("выбрать: sing select <имя>")


def set_custom_proxy_flag(arguments):
    """Ставит флаг своему прокси: «flag <имя> [код страны]»; без кода страна берётся по IP."""
    if not arguments:
        sys.exit("sing: укажи имя: flag <имя> [страна, например GB]")
    custom_links = read_custom_links()
    country_code = ""
    query_words = arguments
    if len(arguments) > 1 and COUNTRY_CODE_PATTERN.match(arguments[-1]):
        country_code, query_words = arguments[-1], arguments[:-1]
    target_link = find_link(custom_links, " ".join(query_words))
    if not target_link:
        sys.exit(f"sing: среди своих нет «{' '.join(query_words)}»")
    if not country_code:
        country_code = lookup_country_code(link_server_host(target_link))
        if not country_code:
            sys.exit("sing: не удалось определить страну по IP, укажи код: flag <имя> GB")
    try:
        updated_link = link_with_flag(target_link, country_code)
    except ValueError as error:
        sys.exit(f"sing: {error}")
    old_name, new_name = link_name(target_link), link_name(updated_link)
    if any(link_name(link) == new_name for link in custom_links if link != target_link):
        sys.exit(f"sing: «{new_name}» уже есть")
    write_custom_links([updated_link if link == target_link else link for link in custom_links])
    # Если это текущий сервер, обновляем и запомненное имя (звёздочка в списке)
    if read_current_name() == old_name:
        with open(CURRENT_SELECTION_FILE, "w") as current_file:
            current_file.write(new_name)
    print(f"{old_name} → {new_name}")


def remove_custom_proxy(query):
    """Удаляет свой прокси из custom.txt по имени."""
    custom_links = read_custom_links()
    link_to_remove = find_link(custom_links, query)
    if not link_to_remove:
        sys.exit(f"sing: среди своих нет «{query}»")
    write_custom_links([link for link in custom_links if link != link_to_remove])
    print(f"удалён: {link_name(link_to_remove)}")


def print_list(custom_links, subscription_links):
    """Печатает свои прокси и серверы подписки, отмечая текущий звёздочкой."""
    current_name = read_current_name()
    for title, links in (("свои", custom_links), ("подписка", subscription_links)):
        if not links:
            continue
        print(f"— {title}:")
        for link in links:
            name = link_name(link)
            marker = "*" if name == current_name else " "
            print(f" {marker} {name}")


def main():
    """Точка входа: список, выбор, добавление или удаление сервера."""
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "add":
        if len(arguments) < 2:
            sys.exit("sing: укажи ссылку или файл: add <ссылка|файл.conf> [имя]")
        add_custom_proxies(arguments[1:])
        return
    if arguments and arguments[0] == "exceptions":
        run_exceptions_command(arguments[1:])
        return
    if arguments and arguments[0] == "flag":
        set_custom_proxy_flag(arguments[1:])
        return
    if arguments and arguments[0] in ("rm", "remove"):
        if len(arguments) < 2:
            sys.exit("sing: укажи имя: rm <имя>")
        remove_custom_proxy(" ".join(arguments[1:]))
        return

    custom_links = read_custom_links()
    if not arguments:
        print_list(custom_links, fetch_subscription_links())
        return
    query = " ".join(arguments)
    # Свои прокси ищем первыми — так не нужно ждать подписку
    selected_link = find_link(custom_links, query) or find_link(fetch_subscription_links(), query)
    if not selected_link:
        sys.exit(f"sing: нет сервера по запросу «{query}»")
    try:
        write_config(selected_link)
    except (ValueError, KeyError, IndexError) as error:
        sys.exit(f"sing: не разобрал ссылку ({error})")
    print(f"выбран: {link_name(selected_link)}")


if __name__ == "__main__":
    main()
