from enum import Enum
from dataclasses import dataclass
from typing import List, Tuple, Any, Optional


class REDIS_TRAFFIC_TYPE(Enum):
    STRING = '+'
    ERROR = '-'
    INTEGER = ':'
    BULKSTR = '$'
    ARRAY = '*'

    UNKNOWN = '?'

    @classmethod
    def query(cls, char: int):
        try:
            return cls(chr(char))
        except ValueError:
            return cls.UNKNOWN


@dataclass
class RedisSerializedPacket:
    type: REDIS_TRAFFIC_TYPE
    content: Any
    length: int | None = None
    is_null: bool = False


class RedisPacket:
    @classmethod
    def parse(cls, raw: bytes) -> List[RedisSerializedPacket]:
        results: List[RedisSerializedPacket] = []
        offset = 0
        while offset < len(raw):
            packet, next_offset = cls._parse_one(raw, offset)
            if packet:
                results.append(packet)
                offset = next_offset
            else:
                break
        return results

    @classmethod
    def _parse_one(
        cls, raw: bytes, offset: int
    ) -> Tuple[Optional[RedisSerializedPacket], int]:
        if offset >= len(raw):
            return None, offset

        first_byte = raw[offset]  # get the type of the packet
        packet_type = REDIS_TRAFFIC_TYPE.query(first_byte)

        line_end = raw.find(b'\r\n', offset)
        if line_end == -1:
            return None, offset

        line_content = raw[offset + 1 : line_end]
        current_pos = line_end + 2

        if packet_type in (
            REDIS_TRAFFIC_TYPE.STRING,
            REDIS_TRAFFIC_TYPE.ERROR,
            REDIS_TRAFFIC_TYPE.INTEGER,
        ):
            # type + content + \r\n
            val = line_content.decode('utf-8', 'ignore')
            if packet_type == REDIS_TRAFFIC_TYPE.INTEGER:
                val = int(val)
            return (
                RedisSerializedPacket(
                    type=packet_type, content=val, length=len(line_content)
                ),
                current_pos,
            )

        elif packet_type == REDIS_TRAFFIC_TYPE.BULKSTR:
            # type + length + \r\n + data + \r\n
            length = int(line_content)
            if length == -1:  # Null Bulk String
                return (
                    RedisSerializedPacket(type=packet_type, content=None, is_null=True),
                    current_pos,
                )

            data = raw[current_pos : current_pos + length]
            return (
                RedisSerializedPacket(type=packet_type, content=data, length=length),
                current_pos + length + 2,
            )

        elif packet_type == REDIS_TRAFFIC_TYPE.ARRAY:
            # type + count + \r\n + packets
            count = int(line_content)
            if count == -1:  # Null Array
                return (
                    RedisSerializedPacket(type=packet_type, content=None, is_null=True),
                    current_pos,
                )

            items: List[RedisSerializedPacket] = []
            for _ in range(count):
                item, current_pos = cls._parse_one(raw, current_pos)
                if item:
                    items.append(item)

            return (
                RedisSerializedPacket(type=packet_type, content=items, length=count),
                current_pos,
            )

        return None, offset
