import os
import socket
import platform
import network

from exception import SetupRequiredError, NotFoundError


class Listener:
    def __init__(self, interface: str):
        self.interface = interface
        self.sniffer = None
        self.sniffer_v6 = None
        self.mix_mode = False
        self.protocol = None
        self.is_setup = False
        self.is_running = False

    def setup(self):
        # Create a raw socket and bind it to the interface
        if platform.system() == "Linux":
            # Linux has AF_PACKET which can capture both IPv4 and IPv6
            self.sniffer = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )
            self.mix_mode = True
        elif platform.system() == "Darwin":
            # MacOS need to set 2 sockets for IPv4 and IPv6
            self.sniffer = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
            )
            try:
                network.get_local_ip(ipv4=False, ipv6=True)  # type: ignore
                self.sniffer_v6 = socket.socket(
                    socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_IPV6
                )
            except NotFoundError:
                print("[!] No ipv6 address found, skipping ipv6 sniffer setup.")
        else:
            # Windows need to turn on ioctl mode
            self.sniffer = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
            )
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            try:
                network.get_local_ip(ipv4=False, ipv6=True)  # type: ignore
                self.sniffer_v6 = socket.socket(
                    socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_IPV6
                )
            except NotFoundError:
                print("[!] No ipv6 address found, skipping ipv6 sniffer setup.")
        # Bind sockets to interface
        if self.mix_mode:
            self.sniffer.bind((self.interface, 0))
        else:
            self.sniffer.bind((network.get_local_ip(interface=self.interface), 0))  # type: ignore
            if self.sniffer_v6:
                self.sniffer_v6.bind((network.get_local_ip(ipv4=False, interface=self.interface), 0))  # type: ignore
        self.is_setup = True

    def start(self):
        if not self.is_setup:
            raise SetupRequiredError("Listener must be set up before starting.")
