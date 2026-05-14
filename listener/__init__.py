import socket
import platform
import network
import selectors
import struct
from typing import Callable

from exception import SetupRequiredError, NotFoundError
from logger import get_logger

logger = get_logger(__name__)


class Listener:
    def __init__(self, interface: str):
        self.interface = interface
        self.interface_idx = -1
        self.sniffer = None
        self.sniffer_v6 = None
        self.mix_mode = False
        self.protocol = None
        self.is_setup = False
        self.is_running = False

    def setup(self):
        # Create a raw socket and bind it to the interface
        logger.info(
            f'Setting up listener on interface {self.interface}, platform: {platform.system()}'
        )
        ipv4_address = network.get_local_ip(self.interface)  # type: ignore
        ipv6_address = None
        self.interface_index = socket.if_nametoindex(self.interface)
        logger.info(f'Interface {self.interface} index: {self.interface_index}')
        try:
            ipv6_address = network.get_local_ip(self.interface, ipv6=True)  # type: ignore
        except NotFoundError:
            logger.warning('[!] No ipv6 address found, skipping ipv6 sniffer setup.')
        if platform.system() == 'Linux':
            # Linux has AF_PACKET which can capture both IPv4 and IPv6
            self.sniffer = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.ntohs(0x0003),  # Raw data with Ethernet header
            )
            self.mix_mode = True
        elif platform.system() == 'Darwin':
            # MacOS need to set 2 sockets for IPv4 and IPv6
            self.sniffer = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
            )
            if ipv6_address:
                self.sniffer_v6 = socket.socket(
                    socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_IPV6
                )
        else:
            # Windows need to turn on ioctl mode
            self.sniffer = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
            )
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            if ipv6_address:
                self.sniffer_v6 = socket.socket(
                    socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_IPV6
                )
                self.sniffer_v6.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        # Bind sockets to interface
        if self.mix_mode:
            self.sniffer.bind((self.interface, 0))
        else:
            self.sniffer.bind((ipv4_address, 0))  # type: ignore
            if self.sniffer_v6:
                try:
                    self.sniffer_v6.bind((ipv6_address, 0, 0, self.interface_index))  # type: ignore
                except OSError as e:
                    if e.errno == 49:
                        logger.warning(f'Triggered exception {e}.')
                        logger.warning(
                            f"Failed to bind IPv6 socket to interface {self.interface} with address {ipv6_address}, falling back to '::' with interface index {self.interface_index}."
                        )
                        self.sniffer_v6.bind(('::', 0, 0, self.interface_index))  # type: ignore
        self.is_setup = True

    def start(self, handler: Callable[[bytes, str], None]):
        if not self.is_setup:
            logger.error('Listener must be set up before starting.')
            raise SetupRequiredError('Listener must be set up before starting.')
        self.is_running = True
        selector = selectors.DefaultSelector()
        if self.sniffer:
            self.sniffer.setblocking(False)
            selector.register(self.sniffer, selectors.EVENT_READ, data='ipv4')
        if self.sniffer_v6:
            self.sniffer_v6.setblocking(False)
            selector.register(self.sniffer_v6, selectors.EVENT_READ, data='ipv6')
        logger.info(f'Listener started on interface {self.interface}')

        while self.is_running:
            events = selector.select(timeout=1)
            for key, mask in events:
                sock = key.fileobj
                protocol = key.data
                packet, addr = sock.recvfrom(65535)
                handler(packet, protocol)
