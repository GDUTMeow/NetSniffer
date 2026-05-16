from dataclasses import dataclass
from enum import Enum
from typing import Literal

from exception import PacketLengthNotSatisfiedError
from logger import get_logger

logger = get_logger(__name__)

class FTPCommand(Enum):
    AUTH = "AUTH"  # 请求认证
    USER = "USER"  # 用户名输入
    PASS = "PASS"  # 密码输入
    OPTS = "OPTS"  # FTP 选项
    PWD = "PWD"  # 显示当前目录
    TYPE = "TYPE"  # 传输类型
    PASV = "PASV"  # 被动模式
    RETR = "RETR"  # 下载文件

    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, command: str) -> "FTPCommand":
        try:
            return cls(command.upper())
        except ValueError:
            return cls.UNKNOWN


class FTPStatusCode(Enum):
    READY = 220
    ASKING_CREDENTIALS = 530
    ASKING_PASSWORD = 331
    LOGIN_SUCCESS = 230
    OPTION_SET_SUCCESS = 200
    OPTION_SET_FAILURE = 504
    CURRENT_DIRECTORY = 257
    OPENING_BINARY_DATA = 150
    TRANSFER_COMPLETE = 226
    ENTRYING_PASV = 227

    UNKNOWN = 0

    @classmethod
    def parse(cls, code: int) -> "FTPStatusCode":
        try:
            return cls(code)
        except ValueError:
            return cls.UNKNOWN

@dataclass
class FTPPassiveModeData:
    addr: str
    port: int


@dataclass
class FTPPacket:
    type: Literal["request", "response"]
    command: FTPCommand | None = None
    args: str | None = None
    pasv_data: FTPPassiveModeData | None = None
    status_code: FTPStatusCode | None = None

    @classmethod
    def parse(cls, raw: bytes) -> "FTPPacket":
        text = raw.decode(encoding="latin-1", errors="ignore")
        parts = text.strip().split(" ", 1)
        if len(parts) == 0:
            raise PacketLengthNotSatisfiedError("Empty FTP packet")
        first = parts[0]
        if first.isdigit():
            packet_type = "response"
            status_code = FTPStatusCode(int(first))
            args = parts[1] if len(parts) > 1 else None
            if status_code == FTPStatusCode.ENTRYING_PASV and args:
                try:
                    if args.startswith("Entering Passive Mode ("):
                        pasv_info = args.split("Entering Passive Mode (")[1].split(")")[0]
                        data_parts = pasv_info.split(",")
                        if len(data_parts) == 6:
                            ip = ".".join(data_parts[:4])
                            port = int(data_parts[4]) * 256 + int(data_parts[5])
                            pasv_data = FTPPassiveModeData(addr=ip, port=port)
                            return cls(type=packet_type, status_code=status_code, args=args, pasv_data=pasv_data)
                except Exception:
                    logger.warning(f"Failed to parse PASV data from FTP response: {args}")
            return cls(type=packet_type, status_code=status_code, args=args)
        else:
            packet_type = "request"
            command = FTPCommand.parse(first)
            args = parts[1] if len(parts) > 1 else None
            return cls(type=packet_type, command=command, args=args)
