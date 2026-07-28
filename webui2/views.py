import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from django.conf import settings as _settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone


@dataclass(frozen=True)
class _ServerEndpoint:
    scheme: str | None
    host: str
    port: int | None
    path: str = ""
    query: str = ""


def _clamp_port(value: int) -> int:
    if value <= 0:
        return 1
    if value > 65535:
        return 65535
    return value


def _offset_port(base: int, offset: int) -> int:
    return _clamp_port(base + offset)


def _default_id_port() -> int:
    return _clamp_port(int(_settings.DEFAULT_ID_PORT))


def _host_without_port(host: str) -> str:
    host = (host or "").strip()
    if host.startswith("["):
        idx = host.find("]")
        if idx > 0:
            return host[1:idx]
    if ":" in host:
        return host.split(":")[0]
    return host


def _split_servers(raw: str) -> list:
    raw = (raw or "").strip()
    if not raw:
        return []
    normalized = raw.replace("\n", ",").replace(";", ",").replace(" ", ",")
    servers = []
    seen = set()
    for item in normalized.split(","):
        server = item.strip()
        if not server or server in seen:
            continue
        seen.add(server)
        servers.append(server)
    return servers


def _strip_ipv6_brackets(host: str) -> str:
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _format_ws_endpoint(
    scheme: str,
    host: str,
    port: int,
    path: str = "",
    query: str = "",
) -> str:
    host = _strip_ipv6_brackets(host)
    if ":" in host:
        host = f"[{host}]"
    suffix = path if path and path != "/" else ""
    if suffix and not suffix.startswith("/"):
        suffix = f"/{suffix}"
    if query:
        suffix = f"{suffix}?{query}"
    return f"{scheme}://{host}:{port}{suffix}"


def _format_host_port(host: str, port: int) -> str:
    host = _strip_ipv6_brackets(host)
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}"


def _parse_server_input(server: str) -> _ServerEndpoint | None:
    server = (server or "").strip()
    if not server or len(server) > 2048 or any(character.isspace() for character in server):
        return None
    if "://" in server:
        try:
            parsed = urlsplit(server)
            scheme = (parsed.scheme or "").lower()
            if scheme not in ("ws", "wss"):
                return None
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                return None
            host = (parsed.hostname or "").strip()
            if not host:
                return None
            try:
                port = parsed.port
            except ValueError:
                return None
            host = _strip_ipv6_brackets(host)
            return _ServerEndpoint(
                scheme=scheme,
                host=host,
                port=port,
                path=parsed.path if parsed.path != "/" else "",
                query=parsed.query,
            )
        except ValueError:
            return None
    if any(character in server for character in "/?#"):
        return None
    if server.startswith("["):
        end = server.find("]")
        if end <= 0:
            return None
        host = _strip_ipv6_brackets(server[1:end])
        rest = server[end + 1 :]
        if not rest:
            return _ServerEndpoint(None, host, None)
        if not rest.startswith(":"):
            return None
        try:
            port = int(rest[1:])
        except ValueError:
            return None
        if port <= 0 or port > 65535:
            return None
        return _ServerEndpoint(None, host, port)
    colon_count = server.count(":")
    if colon_count == 1:
        host, port_text = server.rsplit(":", 1)
        if not host:
            return None
        try:
            port = int(port_text)
        except ValueError:
            return None
        if port <= 0 or port > 65535:
            return None
        host = _strip_ipv6_brackets(host)
        return _ServerEndpoint(None, host, port)
    host = _strip_ipv6_brackets(server)
    if not host:
        return None
    return _ServerEndpoint(None, host, None)


def _normalize_rendezvous_server(server: str) -> str:
    parsed = _parse_server_input(server)
    if not parsed:
        return ""
    if parsed.scheme:
        websocket_port = parsed.port or _offset_port(_default_id_port(), 2)
        default_path = "/ws/id" if parsed.scheme == "wss" else ""
        return _format_ws_endpoint(
            parsed.scheme,
            parsed.host,
            websocket_port,
            parsed.path or default_path,
            parsed.query,
        )
    return _format_host_port(parsed.host, parsed.port or _default_id_port())


def _derive_relay_server(rendezvous_endpoint: str) -> str:
    parsed = _parse_server_input(rendezvous_endpoint)
    if not parsed:
        return ""
    if not parsed.scheme:
        return _format_host_port(
            parsed.host,
            _offset_port(parsed.port or _default_id_port(), 1),
        )
    websocket_port = parsed.port or _offset_port(_default_id_port(), 2)
    if parsed.scheme == "wss":
        # A WSS endpoint is a TLS reverse-proxy origin. Rendezvous and relay
        # share the HTTPS port and are selected by path.
        return _format_ws_endpoint(
            "wss",
            parsed.host,
            websocket_port,
            "/ws/relay",
            parsed.query,
        )
    return _format_ws_endpoint(
        "ws",
        parsed.host,
        _offset_port(websocket_port, 1),
    )


def _normalize_relay_server(
    server: str,
    rendezvous_endpoint: str = "",
) -> str:
    parsed = _parse_server_input(server)
    if not parsed:
        return ""
    fallback = _parse_server_input(rendezvous_endpoint)
    if parsed.scheme == "wss":
        if parsed.port:
            port = parsed.port
        elif fallback and fallback.scheme == "wss":
            port = fallback.port or _offset_port(_default_id_port(), 2)
        else:
            port = _offset_port(_default_id_port(), 3)
        return _format_ws_endpoint(
            "wss",
            parsed.host,
            port,
            parsed.path or "/ws/relay",
            parsed.query,
        )
    if parsed.scheme == "ws":
        if parsed.port:
            port = parsed.port
        elif fallback and fallback.scheme == "ws":
            port = _offset_port(
                fallback.port or _offset_port(_default_id_port(), 2),
                1,
            )
        else:
            port = _offset_port(_default_id_port(), 3)
        return _format_ws_endpoint(
            "ws",
            parsed.host,
            port,
            parsed.path,
            parsed.query,
        )
    base_service_port = fallback.port or _default_id_port() if fallback and not fallback.scheme else _default_id_port()
    return _format_host_port(
        parsed.host,
        parsed.port or _offset_port(base_service_port, 1),
    )


def _resolve_webui2_servers():
    raw_id_servers = _split_servers(_settings.ID_SERVER or "")
    id_servers = []
    for item in raw_id_servers:
        normalized = _normalize_rendezvous_server(item)
        if normalized and normalized not in id_servers:
            id_servers.append(normalized)

    raw_relay_servers = _split_servers(getattr(_settings, "RELAY_SERVER", "") or "")
    relay_servers = []
    fallback_rendezvous = id_servers[0] if id_servers else ""
    for item in raw_relay_servers:
        normalized = _normalize_relay_server(
            item,
            fallback_rendezvous,
        )
        if normalized and normalized not in relay_servers:
            relay_servers.append(normalized)

    if not relay_servers and id_servers:
        derived = []
        for rv in id_servers:
            relay = _derive_relay_server(rv)
            if relay and relay not in derived:
                derived.append(relay)
        relay_servers = derived

    return raw_id_servers, id_servers, relay_servers


@login_required(login_url="/api/user_action?action=login")
def index(request):
    api_server = (_settings.API_SERVER or "").strip()
    raw_id_servers, id_servers, relay_servers = _resolve_webui2_servers()
    id_host = id_servers[0] if id_servers else (raw_id_servers[0] if raw_id_servers else "")
    rs_pub_key = (_settings.RS_PUB_KEY or "").strip()
    context = {
        "domain": id_host,
        "api_server": api_server,
        "rs_pub_key": rs_pub_key,
        "id_server": id_host,
        "relay_server": relay_servers[0] if relay_servers else "",
        "id_servers_json": json.dumps(id_servers),
        "id_servers_csv": ",".join(id_servers),
        "relay_servers_json": json.dumps(relay_servers),
        "relay_servers_csv": ",".join(relay_servers),
        "default_id_port": _default_id_port(),
    }
    return render(request, "webui2.html", context)


@login_required(login_url="/api/user_action?action=login")
def status(request):
    host = _host_without_port(request.get_host())
    raw_id_servers, id_servers, relay_servers = _resolve_webui2_servers()
    id_server = id_servers[0] if id_servers else (raw_id_servers[0] if raw_id_servers else "")
    return JsonResponse(
        {
            "id_server": id_server,
            "id_servers": id_servers,
            "relay_server": relay_servers[0] if relay_servers else "",
            "relay_servers": relay_servers,
            "default_id_port": _default_id_port(),
            "host": host,
            "user": request.user.username or "",
            "is_admin": bool(getattr(request.user, "is_admin", False)),
            "server_time": timezone.now().isoformat(),
        }
    )
