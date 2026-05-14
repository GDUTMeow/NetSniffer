import socket
from socket import AddressFamily, SocketKind
from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6

from exception import OptionError, NotFoundError


class Local:
    # [for (family, type, proto, canoname, sockaddr) in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    ipv4_list: list[
        tuple[
            AddressFamily,
            SocketKind,
            int,
            str,
            tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
        ]
    ] = socket.getaddrinfo(
        socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM
    )
    ipv6_list: list[
        tuple[
            AddressFamily,
            SocketKind,
            int,
            str,
            tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
        ]
    ] = socket.getaddrinfo(
        socket.gethostname(), None, socket.AF_INET6, socket.SOCK_STREAM
    )


def get_local_ip(interface: str, ipv6: bool = False) -> str:
    local_interfaces = interfaces()
    if interface not in local_interfaces:
        raise NotFoundError(f"Interface {interface} not found.")
    family = AF_INET6 if ipv6 else AF_INET
    address = ifaddresses(interface).setdefault(family, [{}])[0].get("addr", "")
    if ipv6:
        # Remove the scope id if present
        address = address.split("%")[0]
    return address


def get_all_local_ip(ipv6: bool = False) -> dict[str, str]:
    ips = {}
    for interface in interfaces():
        if not ipv6:
            family = AF_INET
        else:
            family = AF_INET6
        address = ifaddresses(interface).setdefault(family, [{}])[0].get("addr", "")
        if address:
            if ipv6:
                # Remove the scope id if present
                address = address.split("%")[0]
            ips[interface] = address
    return ips
