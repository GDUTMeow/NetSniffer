from models.application.binary.dns import DNSPacket
from models.application.plain.http import HTTPPacket

SERVICES_PORT_MAPPING = {
    80: 'HTTP',
    443: 'HTTPS',
    22: 'SSH',
    21: 'FTP',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    53: 'DNS',
}

__all__ = ['DNSPacket', 'HTTPPacket', 'SERVICES_PORT_MAPPING']
