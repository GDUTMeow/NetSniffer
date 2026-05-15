from dataclasses import dataclass
from typing import Dict, Optional, Literal
from enum import Enum

from logger import get_logger

logger = get_logger(__name__)


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"
    CONNECT = "CONNECT"


class HTTPVersion(Enum):
    HTTP_1_0 = "HTTP/1.0"
    HTTP_1_1 = "HTTP/1.1"
    # HTTP 2.0 和 3.0 不是纯文本，暂时不考虑
    # HTTP_2_0 = "HTTP/2.0"
    # HTTP_3_0 = "HTTP/3.0"


raw_request = b"""POST /path HTTP/1.1
Host: example.com
Origin: http://example.com
Referer: http://example.com/
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36
Content-Type: application/json
Content-Length: 1050

some_body_here
"""

raw_resp = b"""HTTP/1.1 200 OK
date: Thu, 09 Apr 2026 12:29:19 GMT
server: uvicorn
content-type: text/plain; charset=utf-8
access-control-allow-origin: http://example.com
access-control-allow-credentials: true
vary: Origin
Content-Length: 952

some_resp_here
"""


@dataclass
class HTTPPacket:
    packet_type: Literal["request", "response"]
    method: Optional[HTTPMethod] = None
    path: Optional[str] = None
    version: Optional[HTTPVersion] = None
    status_code: Optional[int] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[bytes] = None

    @classmethod
    def parse(cls, raw: bytes) -> Optional["HTTPPacket"]:
        if not raw:
            return None
        packet_type = method = path = version = status_code = body = None
        headers = {}
        try:
            content = raw.decode("latin-1", errors="replace")
            lines = content.splitlines()
            if not lines:
                return None
            first_line = lines[0]
            if first_line.startswith("HTTP/"):
                packet_type = "response"
                line_content = first_line.split(" ", 2)
                try:
                    version = HTTPVersion(line_content[0])
                except ValueError:
                    version = None
                    logger.warning(f"Unknown HTTP version: {line_content[0]}, unable to parse HTTP packet.")
                    return None
                status_code = int(line_content[1])
            else:
                packet_type = "request"
                line_content = first_line.split(" ", 2)
                try:
                    method = HTTPMethod(line_content[0])
                except ValueError:
                    logger.warning(f"Unknown HTTP method: {line_content[0]}, unable to parse HTTP packet.")
                    return None
                path = line_content[1]
                try:
                    version = HTTPVersion(line_content[2])
                except ValueError:
                    version = None
                    logger.warning(f"Unknown HTTP version: {line_content[2]}, unable to parse HTTP packet.")
                    return None
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if line == "\r\n" or line == "":
                    break  # HTTP 是双空行分割头部和正文，遇到空行肯定就没有头部了
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else None
            if packet_type == "request":
                return cls(
                    packet_type=packet_type,
                    method=method,
                    path=path,
                    version=version,
                    headers=headers,
                    body=body,
                )
            else:
                return cls(
                    packet_type=packet_type,
                    version=version,
                    status_code=status_code,
                    headers=headers,
                    body=body,
                )
        except Exception as e:
            logger.debug(f"Raw HTTP packet content: {raw}")
            logger.error(f"Error parsing HTTP packet: {e}")
            return None

if __name__ == "__main__":
    raw_request = raw_request.replace(b"\n", b"\r\n")
    raw_resp = raw_resp.replace(b"\n", b"\r\n")
    packet = HTTPPacket.parse(raw_request)
    print(packet)
    packet = HTTPPacket.parse(raw_resp)
    print(packet)