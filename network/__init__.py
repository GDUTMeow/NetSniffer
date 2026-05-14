import socket
from socket import AddressFamily, SocketKind

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
    ] = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM)
    ipv6_list: list[
        tuple[
            AddressFamily,
            SocketKind,
            int,
            str,
            tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
        ]
    ] = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6, socket.SOCK_STREAM)


def get_local_ip(
    ipv4: bool = True, ipv6: bool = False, prefix: str | None = None, interface: str | None = None
) -> str:
    if not ipv4 and not ipv6:
        raise OptionError("Neither IPv4 nor IPv6 is chosen.")
    if prefix is not None and interface is not None:
        raise OptionError("Cannot specify both prefix and interface.")
    if not interface:
        if ipv4:
            for _, _, _, _, sockaddr in Local.ipv4_list:
                if prefix is None or sockaddr[0].startswith(prefix):    # type: ignore
                    return str(sockaddr[0])
        if ipv6:
            for _, _, _, _, sockaddr in Local.ipv6_list:
                if prefix is None or sockaddr[0].startswith(prefix):    # type: ignore
                    return str(sockaddr[0])
    else:
        # Use the interface name specified to get the IP address
        if ipv4:
            for _, _, _, canonname, sockaddr in Local.ipv4_list:
                if canonname == interface:
                    return str(sockaddr[0])
        if ipv6:
            for _, _, _, canonname, sockaddr in Local.ipv6_list:
                if canonname == interface:
                    return str(sockaddr[0])
    raise NotFoundError(f"No matching local IP address matching prefix={prefix}, interface={interface} found.")

def get_all_local_ip(
    ipv4: bool = True, ipv6: bool = False, prefix: str | None = None, interface: str | None = None
) -> list[str]:
    if not ipv4 and not ipv6:
        raise OptionError("Neither IPv4 nor IPv6 is chosen.")
    result: list[str] = []
    if ipv4:
        for _, _, _, _, sockaddr in Local.ipv4_list:
            if prefix is None or sockaddr[0].startswith(prefix):    # type: ignore
                result.append(str(sockaddr[0]))
    if ipv6:
        for _, _, _, _, sockaddr in Local.ipv6_list:
            if prefix is None or sockaddr[0].startswith(prefix):    # type: ignore
                result.append(str(sockaddr[0]))
    return result
