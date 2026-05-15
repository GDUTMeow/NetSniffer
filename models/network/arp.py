import struct
import socket
from dataclasses import dataclass
from enum import Enum

from exception import PacketLengthNotSatisfiedError


class ARPType(Enum):
    REQUEST = 1
    REPLY = 2

    UNKNOWN = 255

    @classmethod
    def query(cls, value: int):
        try:
            return cls(value).name
        except ValueError:
            return f"Unknown (0x{value:04X})"


@dataclass
class ARPPacket:
    hardware_type: int  # 16 bits
    protocol_type: int  # 16 bits
    hardware_size: int  # 8 bits
    protocol_size: int  # 8 bits
    opcode: ARPType  # 16 bits
    src_mac: str  # 48 bits
    src_ip: str  # 32 bits
    dst_mac: str  # 48 bits
    dst_ip: str  # 32 bits

    @classmethod
    def parse(cls, raw_data: bytes) -> "ARPPacket":
        if len(raw_data) < 28:
            raise PacketLengthNotSatisfiedError(
                "ARP packet must be at least 28 bytes long."
            )
        (
            hardware_type,
            protocol_type,
            hardware_size,
            protocol_size,
            opcode,
            src_mac,
            src_ip,
            dst_mac,
            dst_ip,
        ) = struct.unpack("!HHBBH6s4s6s4s", raw_data[:28])
        return cls(
            hardware_type=hardware_type,
            protocol_type=protocol_type,
            hardware_size=hardware_size,
            protocol_size=protocol_size,
            opcode=ARPType.query(opcode),
            src_mac=":".join(f"{b:02x}" for b in src_mac),
            src_ip=socket.inet_ntoa(src_ip),
            dst_mac=":".join(f"{b:02x}" for b in dst_mac),
            dst_ip=socket.inet_ntoa(dst_ip),
        )
