import struct
from enum import Enum
from dataclasses import dataclass
from models.network.ip import IPv4Packet, IPv6Packet


class ICMPType(Enum):
    # SUCCESS
    REQUEST = 8
    REPLY = 0

    # ERROR
    DST_UNREACHABLE = 3
    TIME_EXCEEDED = 11

    # REDIRECT
    REDIRECT = 5


@dataclass
class ICMPData:
    ts: int | None  # 64 bits timestamp
    data: bytes  # ICMP payload data

    @classmethod
    def parse(cls, raw: bytes) -> 'ICMPData':
        if len(raw) < 8:
            # Windows 不带时间戳
            ts = None
            data = raw
        else:
            (ts,) = struct.unpack('!Q', raw[:8])  # 8 bytes timestamp
            data = raw[8:]  # rest is data
        return cls(ts=ts, data=data)


@dataclass
class ICMPv4Packet(IPv4Packet):
    type: ICMPType  # 8 bits
    code: int  # 8 bits
    icmp_checksum: int  # 16 bits
    identifier: int  # 16 bits
    sequence_number: int  # 16 bits
    data: ICMPData  # ICMP payload data

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
            type=ICMPType(type),
            code=code,
            icmp_checksum=icmp_checksum,
            identifier=identifier,
            sequence_number=sequence_number,
            data=icmpdata,
        )


class ICMPv6Packet(IPv6Packet): ...
