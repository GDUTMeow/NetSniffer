from models.application.binary.dns import DNSPacket
from models.application.binary.ntp import NTPPacket
from models.application.plain.http import HTTPPacket
from models.application.plain.redis import RedisPacket
from models.application.plain.ftp import FTPPacket

SERVICES_PORT_MAPPING = {
    80: 'HTTP',
    21: 'FTP',
    53: 'DNS',
    123: 'NTP',
    6379: 'Redis',
}

__all__ = ['DNSPacket', 'HTTPPacket', 'NTPPacket', 'RedisPacket', 'FTPPacket', 'SERVICES_PORT_MAPPING']
