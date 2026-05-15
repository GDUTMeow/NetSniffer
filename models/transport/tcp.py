import struct
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from exception import MalformedTCPOptionError
from logger import get_logger

logger = get_logger(__name__)


class TCPOptionOperation(Enum):
    END_OF_OPTION_LIST = 0
    NO_OPERATION = 1
    MAXIMUM_SEGMENT_SIZE = 2
    WINDOW_SCALE = 3
    SACK_PERMITTED = 4  # Selective Acknowledgment Permitted
    SACK = 5  # Selective Acknowledgment
    TIMESTAMP = 8  # Timestamp and echo of previous timestamp
    USER_TIMEOUT_OPTION = 28
    TCP_AO = 29  # TCP Authentication Option
    MPTCP = 30  # Multipath TCP
    UNKNOWN = 255

    @classmethod
    def query(cls, value: int) -> Optional['TCPOptionOperation']:
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


@dataclass
class TCPOptionItem:
    kind: TCPOptionOperation
    length: int
    data: bytes | int | None


@dataclass
class TCPFlags:
    flag_rev: int  # 4 bits
    flag_cwr: int  # 1 bit
    flag_ece: int  # 1 bit
    flag_urg: int  # 1 bit
    flag_ack: int  # 1 bit
    flag_psh: int  # 1 bit
    flag_rst: int  # 1 bit
    flag_syn: int  # 1 bit
    flag_fin: int  # 1 bit

    @classmethod
    def parse(cls, raw: int) -> 'TCPFlags':
        return cls(
            flag_rev=(raw >> 8) & 0xF,
            flag_cwr=(raw >> 7) & 0x1,
            flag_ece=(raw >> 6) & 0x1,
            flag_urg=(raw >> 5) & 0x1,
            flag_ack=(raw >> 4) & 0x1,
            flag_psh=(raw >> 3) & 0x1,
            flag_rst=(raw >> 2) & 0x1,
            flag_syn=(raw >> 1) & 0x1,
            flag_fin=raw & 0x1,
        )


class TCPOptions:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.options: List[TCPOptionItem] = []
        self._parse_options(raw)

    def _parse_options(self, raw: bytes):
        idx = 0
        while idx < len(raw):
            cur = raw[idx]
            if cur == TCPOptionOperation.END_OF_OPTION_LIST.value:
                break  # Reached the end of options
            elif cur == TCPOptionOperation.NO_OPERATION.value:
                self.options.append(
                    TCPOptionItem(TCPOptionOperation.NO_OPERATION, 1, None)
                )
                idx += 1
            else:
                operation = TCPOptionOperation.query(cur)
                if operation is None:
                    logger.warning(f'Unknown TCP option kind: {cur}')
                    operation = TCPOptionOperation.UNKNOWN
                    if idx + 1 >= len(raw):
                        logger.warning(
                            f'Option {operation} at index {idx} has no length byte, breaking parsing.'
                        )
                        break
                datalen = raw[idx + 1]
                if datalen < 2:
                    raise MalformedTCPOptionError(
                        f'Invalid TCP option length: {datalen} for option {operation}'
                    )
                opdata = raw[idx + 2 : idx + datalen]
                if (
                    operation == TCPOptionOperation.MAXIMUM_SEGMENT_SIZE
                    and len(opdata) == 2
                ):
                    opdata = struct.unpack('!H', opdata)[0]  # Unpack MSS value
                elif operation == TCPOptionOperation.WINDOW_SCALE and len(opdata) == 1:
                    opdata = opdata[0]  # Unpack Window Scale value
                self.options.append(TCPOptionItem(operation, datalen, opdata))
                idx += datalen


@dataclass
class TCPPacket:
    # Ref: https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    src_port: int  # 16 bits
    dst_port: int  # 16 bits
    sequence_number: int  # 32 bits
    acknowledgement_number: int  # 32 bits
    offset: int  # 4 bits
    flags: TCPFlags  # 12 bits
    window: int  # 16 bits
    checksum: int  # 16 bits
    urgent_pointer: int  # 16 bits
    options: TCPOptions
    payload: bytes = b''

    @classmethod
    def parse(cls, raw_data: bytes) -> 'TCPPacket':
        (
            src_port,
            dst_port,
            sequence_number,
            acknowledgement_number,
            off_flags,
            window,
            checksum,
            urgent_pointer,
        ) = struct.unpack('!HHLLHHHH', raw_data[:20])
        offset = (off_flags >> 12) & 0xF
        flags = TCPFlags.parse(off_flags & 0xFFF)
        header_length = offset * 4
        options = raw_data[20:header_length] if header_length > 20 else b''
        payload = raw_data[header_length:]
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            sequence_number=sequence_number,
            acknowledgement_number=acknowledgement_number,
            offset=offset,
            flags=flags,
            window=window,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
            options=TCPOptions(options),
            payload=payload,
        )
