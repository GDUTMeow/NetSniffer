from typing import TypedDict, Optional, Dict, Any

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
from manage import packet_manager

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
        ethernet_frame = self.parse_ethernet(raw_data)
        logger.debug(
            f'Parsed Ethernet frame: src={ethernet_frame.src_mac}, dst={ethernet_frame.dst_mac}, ethertype={ethernet_frame.ethertype}'
        )
        network_packet = self.parse_network(
            ethernet_frame.payload, ethernet_frame.ethertype
        )
        logger.debug(
            f'Parsed Network packet: {type(network_packet).__name__ if network_packet else "None"}'
        )

        transport_packet = None
        application_packet = None
        label = 'Unknown'

        if isinstance(network_packet, ARPPacket):
            label = 'ARP'
            logger.debug(
                'Parsed ARP packet, skipping transport and application parsing.'
            )
        elif isinstance(network_packet, (ICMPv4Packet, ICMPv6Packet)):
            label = 'ICMPv4' if isinstance(network_packet, ICMPv4Packet) else 'ICMPv6'
            logger.debug(
                f'Parsed {label} packet, skipping transport and application parsing.'
            )
        elif isinstance(network_packet, (IPv4Packet, IPv6Packet)):
            proto_num = (
                network_packet.protocol
                if isinstance(network_packet, IPv4Packet)
                else network_packet.next_header
            )
            transport_packet = self.parse_transport(network_packet.payload, proto_num)
            if transport_packet:
                label = 'TCP' if isinstance(transport_packet, TCPPacket) else 'UDP'
                logger.debug(
                    f'Parsed {label} packet, checking for application layer parsing.'
                )
                service = SERVICES_PORT_MAPPING.get(
                    transport_packet.src_port
                ) or SERVICES_PORT_MAPPING.get(transport_packet.dst_port)
                application_packet = self.parse_application(
                    transport_packet.payload, service
                )
                if application_packet:
                    label = service
                    logger.debug(f'Parsed application layer protocol: {service}')
                    logger.debug(f'Application packet details: {application_packet}')
                else:
                    logger.debug('No application layer protocol identified.')
                    logger.debug(f'Transport packet details: {transport_packet}')
            else:
                label = 'IPv4' if isinstance(network_packet, IPv4Packet) else 'IPv6'
                logger.debug(
                    f'No transport layer protocol identified, labeling as {label}.'
                )
                logger.debug(f'Network packet details: {network_packet}')
        else:
            label = ethernet_frame.ethertype.name
            logger.debug(f'Unknown network layer protocol, labeling as {label}.')
            logger.debug(f'Ethernet frame details: {ethernet_frame}')

        parsed_dict: Dict[str, Any] = {
            'raw': raw_data,
            'ethernet': ethernet_frame,
            'network': network_packet,
            'transport': transport_packet,
            'application': application_packet,
        }
        logger.debug(
            f'Adding packet to manager: {label if label is not None else "Unknown"}'
        )
        packet_manager.add_packet(
            parsed_dict, label=label if label is not None else 'Unknown'
        )
        return ParsedResult(**parsed_dict)

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
