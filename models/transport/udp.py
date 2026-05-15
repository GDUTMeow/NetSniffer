import struct
from dataclasses import dataclass


@dataclass
class UDPPacket:
    src_post: int  # 16 bits
    dst_port: int  # 16 bits
    length: int  # 16 bits
    checksum: int  # 16 bits
    payload: bytes = b''

    @classmethod
    def parse(cls, raw_data: bytes) -> 'UDPPacket':
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', raw_data[:8])
        payload = raw_data[8:]
        return cls(
            src_post=src_port,
            dst_port=dst_port,
            length=length,
            checksum=checksum,
            payload=payload,
        )
