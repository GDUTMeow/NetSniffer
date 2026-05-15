from models.datalink import EthernetFrame
from models.network import IPv4Packet, IPv6Packet, ICMPv4Packet, ICMPv6Packet, ARPPacket
from models.transport import TCPPacket, UDPPacket
from logger import get_logger

logger = get_logger(__name__)


class Parser:
    def __init__(self):
        pass

    def parse_ethernet(self, raw_data: bytes, protocol: str) -> EthernetFrame:
        print(
            f'Parsing Ethernet frame from raw data: {raw_data.hex()}: {EthernetFrame.parse(raw_data)}'
        )
        return EthernetFrame.parse(raw_data)
