from typing import TypedDict, Optional

from models.datalink import EthernetFrame, EtherType
from models.network import IPv4Packet, IPv6Packet, ICMPv4Packet, ICMPv6Packet, ARPPacket
from models.transport import TCPPacket, UDPPacket
from models.application import (
    DNSPacket,
    HTTPPacket,
    NTPPacket,
    RedisPacket,
    FTPPacket,
    SERVICES_PORT_MAPPING,
)
from logger import get_logger

logger = get_logger(__name__)


class ParsedResult(TypedDict):
    raw: bytes
    ethernet: EthernetFrame
    network: Optional[IPv4Packet | IPv6Packet | ICMPv4Packet | ICMPv6Packet | ARPPacket]
    transport: Optional[TCPPacket | UDPPacket]
    application: Optional[DNSPacket | HTTPPacket | NTPPacket | RedisPacket | FTPPacket]


class Parser:
    def __init__(self):
        pass

    def parse(self, raw_data: bytes) -> ParsedResult:
        # Parse ethernet frame
        ethernet_frame = self.parse_ethernet(raw_data)
        logger.debug(f'Parsed Ethernet Frame: {ethernet_frame}')
        # Parse network layer
        network_packet = self.parse_network(
            ethernet_frame.payload, ethernet_frame.ethertype
        )
        logger.debug(f'Parsed Network Packet: {network_packet}')
        # Parse transport layer
        if isinstance(network_packet, (IPv4Packet, IPv6Packet)):
            transport_packet = self.parse_transport(
                network_packet.payload,
                (
                    network_packet.protocol
                    if isinstance(network_packet, IPv4Packet)
                    else network_packet.next_header
                ),
            )
            logger.debug(f'Parsed Transport Packet: {transport_packet}')
            # Parse application layer
            if transport_packet is None:
                logger.warning(
                    'Transport packet is None, cannot parse application layer'
                )
                return ParsedResult(
                    raw=raw_data,
                    ethernet=ethernet_frame,
                    network=network_packet,
                    transport=None,
                    application=None,
                )
            service = SERVICES_PORT_MAPPING.get(
                transport_packet.src_port
            ) or SERVICES_PORT_MAPPING.get(transport_packet.dst_port)
            application_packet = self.parse_application(
                transport_packet.payload, service
            )
            logger.debug(f'Parsed Application Packet: {application_packet}')
            return ParsedResult(
                raw=raw_data,
                ethernet=ethernet_frame,
                network=network_packet,
                transport=transport_packet,
                application=application_packet,
            )
        else:
            return ParsedResult(
                raw=raw_data,
                ethernet=ethernet_frame,
                network=network_packet,
                transport=None,
                application=None,
            )

    def parse_ethernet(self, raw_data: bytes) -> EthernetFrame:
        return EthernetFrame.parse(raw_data)

    def parse_network(
        self,
        raw_data: bytes,
        protocol: EtherType,
    ) -> ICMPv4Packet | IPv4Packet | ICMPv6Packet | IPv6Packet | ARPPacket | None:
        if protocol == EtherType.IPV4:
            packet = IPv4Packet.parse(raw_data)
            if packet.protocol == 1:  # ICMP
                return ICMPv4Packet.parse(raw_data)
            else:
                return packet
        elif protocol == EtherType.IPV6:
            packet = IPv6Packet.parse(raw_data)
            if packet.next_header == 58:  # ICMPv6
                return ICMPv6Packet.parse(raw_data)
            else:
                return packet
        elif protocol == EtherType.ARP:
            return ARPPacket.parse(raw_data)

    def parse_transport(
        self, raw_data: bytes, protocol: int
    ) -> TCPPacket | UDPPacket | None:
        if protocol == 6:  # TCP
            return TCPPacket.parse(raw_data)
        elif protocol == 17:  # UDP
            return UDPPacket.parse(raw_data)

    def parse_application(
        self,
        raw_data: bytes,
        service: str | None,
    ):
        if service == 'HTTP':
            return HTTPPacket.parse(raw_data)
        elif service == 'FTP':
            return FTPPacket.parse(raw_data)
        elif service == 'DNS':
            return DNSPacket.parse(raw_data)
        elif service == 'NTP':
            return NTPPacket.parse(raw_data)
        elif service == 'Redis':
            return RedisPacket.parse(raw_data)
        else:
            logger.warning(
                'Unknown application protocol, cannot parse application layer'
            )
            return None
