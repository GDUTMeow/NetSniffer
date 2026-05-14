from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6

from exception import NotFoundError
from logger import get_logger

logger = get_logger(__name__)


def is_global_ipv6(ipv6: str) -> bool:
    return not (
        ipv6.startswith('fe80:')  # Local loopback
        or ipv6.startswith('::1')  # Localhost
    )


def get_local_ip(interface: str, ipv6: bool = False) -> str:
    logger.debug(
        f'Getting local IP{"v4" if not ipv6 else "v6"} address for interface {interface}'
    )
    local_interfaces = interfaces()
    if interface not in local_interfaces:
        raise NotFoundError(f'Interface {interface} not found.')
    family = AF_INET6 if ipv6 else AF_INET
    all_address = ifaddresses(interface).get(family, [])
    if not all_address:
        raise NotFoundError(
            f'No {"IPv6" if ipv6 else "IPv4"} address found for interface {interface}.'
        )
    addresses = [addr.get('addr', '') for addr in all_address if addr.get('addr', '')]
    if ipv6:
        filtered_addresses = [addr for addr in addresses if is_global_ipv6(addr)]
        if not filtered_addresses:
            raise NotFoundError(
                f'No global IPv6 address found for interface {interface}.'
            )
        address = filtered_addresses[0]
    else:
        address = addresses[0]
    logger.debug(f'Retrieved IP for interface {interface}: {address}')
    if ipv6:
        # Remove the scope id if present
        # fucking ipv6 contain this stuff
        address = address.split('%')[0]
    logger.info(
        f'Local IP{"v4" if not ipv6 else "v6"} address for interface {interface}: {address}'
    )
    return address


def get_all_local_ip(ipv6: bool = False) -> dict[str, str]:
    ips = {}
    for interface in interfaces():
        logger.debug(f'Processing interface {interface} (IPv6={ipv6})')
        if not ipv6:
            family = AF_INET
        else:
            family = AF_INET6
        address = ifaddresses(interface).setdefault(family, [{}])[0].get('addr', '')
        if address:
            if ipv6:
                # Remove the scope id if present
                address = address.split('%')[0]
            ips[interface] = address
    logger.info(f'All local IPs (IPv6={ipv6}): {ips}')
    return ips
