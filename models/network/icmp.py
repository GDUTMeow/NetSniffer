import struct
from enum import Enum
from dataclasses import dataclass
from models.network.ip import IPv4Packet, IPv6Packet


class ICMPType(Enum):
    # SUCCESS
    IPv4_REQUEST = 8
    IPv4_REPLY = 0
    IPv6_REQUEST = 128
    IPv6_RESPONSE = 129

    # ERROR
    DST_UNREACHABLE = 3
    TIME_EXCEEDED = 11
    NO_ROUTE_TO_DST = 1

    # REDIRECT
    REDIRECT = 5

    # OTHER
    NEIGHBOR_SOLICIT = 135
    NEIGHBOR_ADVERTISEMENT = 136
    MULTICAST_LISTENER_REPORT = 143


@dataclass
class ICMPv6Flags:
    router: int  # 1 bit
    solicited: int  # 1 bit
    override: int  # 1 bit
    reversed: int  # 29 bits

    @classmethod
    def parse(cls, raw: int) -> 'ICMPv6Flags':
        return cls(
            router=(raw >> 31) & 0x1,
            solicited=(raw >> 30) & 0x1,
            override=(raw >> 29) & 0x1,
            reversed=raw & 0x1FFFFFFF,
        )


@dataclass
class ICMPData:
    ts: int | None  # 64 bits timestamp
    data: bytes  # ICMP payload data

    @classmethod
    def parse(cls, raw: bytes) -> 'ICMPData':
        if len(raw) == 32:
            # Windows 不带时间戳
            ts = None
            data = raw
        else:
            (ts,) = struct.unpack('!Q', raw[:8])  # 8 bytes timestamp
            data = raw[8:]  # rest is data
        return cls(ts=ts, data=data)


@dataclass
class ICMPv4Packet(IPv4Packet):
    icmp_type: ICMPType  # 8 bits
    icmp_code: int  # 8 bits
    icmp_checksum: int  # 16 bits
    icmp_identifier: int  # 16 bits
    icmp_sequence_number: int  # 16 bits
    icmp_data: ICMPData  # ICMP payload data

    @classmethod
    def parse(cls, raw_data: bytes) -> 'ICMPv4Packet':
        packet = super().parse(raw_data)
        type, code, icmp_checksum, identifier, sequence_number = struct.unpack(
            '!BBHHH', bytes(packet.payload[:8])
        )
        icmpdata = ICMPData.parse(packet.payload[8:])
        return cls(
            version=packet.version,
            head_length=packet.head_length,
            service=packet.service,
            length=packet.length,
            identification=packet.identification,
            flags=packet.flags,
            fragment_offset=packet.fragment_offset,
            ttl=packet.ttl,
            protocol=packet.protocol,
            checksum=packet.checksum,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            payload=packet.payload,
            icmp_type=ICMPType(type),
            icmp_code=code,
            icmp_checksum=icmp_checksum,
            icmp_identifier=identifier,
            icmp_sequence_number=sequence_number,
            icmp_data=icmpdata,
        )


@dataclass
class ICMPv6Packet(IPv6Packet):
    icmp_type: ICMPType  # 8 bits
    icmp_code: int  # 8 bits
    icmp_checksum: int  # 16 bits
    icmp_identifier: int  # 16 bits
    icmp_sequence_number: int  # 16 bits
    icmp_data: ICMPData  # ICMP payload data

    @classmethod
    def parse(cls, raw_data: bytes) -> 'ICMPv6Packet':
        packet = super().parse(raw_data)
        type, code, checksum, identifier, sequence_number = struct.unpack(
            '!BBHHH', bytes(packet.payload[:8])
        )
        icmpdata = ICMPData.parse(packet.payload[8:])
        return cls(
            version=packet.version,
            traffic_class=packet.traffic_class,
            flow_label=packet.flow_label,
            length=packet.length,
            next_header=packet.next_header,
            hop_limit=packet.hop_limit,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            payload=packet.payload,
            icmp_type=ICMPType(type),
            icmp_code=code,
            icmp_checksum=checksum,
            icmp_identifier=identifier,
            icmp_sequence_number=sequence_number,
            icmp_data=icmpdata,
        )
