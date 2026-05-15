import struct
import socket
from dataclasses import dataclass


@dataclass
class IPv4Packet:
    version: int  # 4 bits
    head_length: int  # 4 bits
    service: int  # 8 bits
    length: int  # 16 bits
    identification: int  # 16 bits
    flags: int  # 3 bits
    fragment_offset: int  # 13 bits
    ttl: int  # 8 bits
    protocol: int  # 8 bits
    checksum: int  # 16 bits
    src_ip: str  # 32 bits
    dst_ip: str  # 32 bits
    payload: bytes  # IP 包的内容载荷

    @classmethod
    def parse(cls, raw_data: bytes) -> 'IPv4Packet':
        (
            ver_head,  # 8 bits -> version + head_length
            service,
            length,
            identification,
            flag_and_offset,  # 16 bits -> flags + fragment_offset
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
        ) = struct.unpack('!BBHHHBBH4s4s', raw_data[:20])
        version, head_length = ver_head >> 4, ver_head & 0x0F
        flags, fragment_offset = flag_and_offset >> 13, flag_and_offset & 0x1FFF
        payload = raw_data[head_length * 4 :]
        return IPv4Packet(
            version=version,
            head_length=head_length,
            service=service,
            length=length,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            src_ip=socket.inet_ntoa(src_ip),
            dst_ip=socket.inet_ntoa(dst_ip),
            payload=payload,
        )


@dataclass
class IPv6TrafficClass:
    dscp: int  # 6 bits
    ecn: int  # 2 bits

    @classmethod
    def parse(cls, raw: int) -> 'IPv6TrafficClass':
        dscp = raw >> 2
        ecn = raw & 0x03
        return cls(dscp=dscp, ecn=ecn)


@dataclass
class IPv6Packet:
    version: int  # 4 bits
    traffic_class: IPv6TrafficClass  # 8 bits
    flow_label: int  # 20 bits
    length: int  # 16 bits
    next_header: int  # 8 bits
    hop_limit: int  # 8 bits
    src_ip: str  # 128 bits
    dst_ip: str  # 128 bits
    payload: bytes  # IP 包的内容载荷

    @classmethod
    def parse(cls, raw_data: bytes) -> 'IPv6Packet':
        ver_tc_fl, length, next_header, hop_limit, src_ip, dst_ip = struct.unpack(
            '!IHBB16s16s', raw_data[:40]
        )
        version = ver_tc_fl >> 28
        traffic_class = IPv6TrafficClass.parse(ver_tc_fl >> 20 & 0xFF)
        flow_label = ver_tc_fl & 0xFFFFF
        payload = raw_data[40:]
        return IPv6Packet(
            version=version,
            traffic_class=traffic_class,
            flow_label=flow_label,
            length=length,
            next_header=next_header,
            hop_limit=hop_limit,
            src_ip=socket.inet_ntop(socket.AF_INET6, src_ip),
            dst_ip=socket.inet_ntop(socket.AF_INET6, dst_ip),
            payload=payload,
        )
