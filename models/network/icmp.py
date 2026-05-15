import struct
import socket
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
    ROUTER_ADVERTISEMENT = 134
    NEIGHBOR_SOLICIT = 135
    NEIGHBOR_ADVERTISEMENT = 136
    MULTICAST_LISTENER_REPORT = 143

    # UNKNOWN
    UNKNOWN = 255

    @classmethod
    def query(cls, value: int):
        try:
            return cls(value).name
        except ValueError:
            return f'Unknown (0x{value:02X})'


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
class NDPOption:
    ndp_type: int  # 8 bits
    length: int  # 8 bits
    link_layer_addr: str | None  # 48 bits，可能没有

    @classmethod
    def parse(cls, raw: bytes) -> 'NDPOption':
        ndp_type, length = struct.unpack('!BB', raw[:2])
        if ndp_type in (1, 2):  # Source/Target Link-Layer Address
            link_layer_addr = ':'.join(f'{b:02x}' for b in raw[2:8])  # 6 bytes
        else:
            link_layer_addr = None
        return cls(
            ndp_type=ndp_type,
            length=length,
            link_layer_addr=link_layer_addr,
        )


@dataclass
class ICMPData:
    ts: int | None  # 64 bits timestamp
    target_addr: str | None  # 128 bits IPv6 地址，NDP 处理用
    ndp_options: NDPOption | None  # NDP 选项列表
    data: bytes  # ICMP payload data

    @classmethod
    def parse(cls, raw: bytes, is_ndp: bool = False) -> 'ICMPData':
        if not is_ndp:
            # 正常 ping，直接解析一下
            if len(raw) == 32:
                # Windows 不带时间戳
                ts = None
                data = raw
            else:
                (ts,) = struct.unpack('!Q', raw[:8])  # 8 bytes timestamp
                data = raw[8:]  # rest is data
            target_addr = None
            ndp_options = None
        else:
            # NDP 要特殊处理一下
            ts = None
            target_addr = socket.inet_ntop(
                socket.AF_INET6, raw[:16]
            )  # 16 bytes IPv6 address
            ndp_options = NDPOption.parse(raw[16:])  # rest is NDP options
            data = raw[16:]
        return cls(ts=ts, data=data, target_addr=target_addr, ndp_options=ndp_options)


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
    icmp_identifier: int | None  # 16 bits，NDP 没有这个
    icmp_sequence_number: int | None  # 16 bits，NDP 没有这个
    icmp_reversed: int | None  # 32 bits，NDP 有这个
    icmp_data: ICMPData  # ICMP payload data

    @classmethod
    def parse(cls, raw_data: bytes) -> 'ICMPv6Packet':
        packet = super().parse(raw_data)
        type, code, checksum = struct.unpack('!BBH', bytes(packet.payload[:4]))
        if type in (
            ICMPType.IPv6_REQUEST,
            ICMPType.IPv6_RESPONSE,
        ):
            identifier, sequence_number = struct.unpack(
                '!HH', bytes(packet.payload[4:8])
            )
            icmpdata = ICMPData.parse(packet.payload[8:])
            icmp_reversed = None
        else:
            identifier = None
            sequence_number = None
            (icmp_reversed,) = struct.unpack('!I', bytes(packet.payload[4:8]))
            icmpdata = ICMPData.parse(packet.payload[8:], is_ndp=True)
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
            icmp_reversed=icmp_reversed,
            icmp_data=icmpdata,
        )
