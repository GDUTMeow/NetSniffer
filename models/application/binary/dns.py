import struct
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple

from exception import PacketLengthNotSatisfiedError, CursorOutOfBoundsError


class DNSQueryType(Enum):
    # Ref: https://en.wikipedia.org/wiki/List_of_DNS_record_types
    A = 1
    AAAA = 28
    AFSDB = 18
    APL = 42
    CAA = 257
    CDNSKEY = 60
    CDS = 59
    CERT = 37
    CNAME = 5
    CSYNC = 62
    DHCID = 49
    DLV = 32769
    DNAME = 39
    DNSKEY = 48
    DS = 43
    EUI48 = 108
    EUI64 = 109
    HINFO = 13
    HIP = 55
    HTTPS = 65
    IPSECKEY = 45
    KEY = 25
    KX = 36
    LOC = 29
    MX = 15
    NAPTR = 35
    NS = 2
    NSEC = 47
    NSEC3 = 50
    NSEC3PARAM = 51
    OPENGPGKEY = 61
    PTR = 12
    RP = 17
    RRSIG = 46
    SIG = 24
    SMIMEA = 53
    SOA = 6
    SRV = 33
    SSHFP = 44
    SVCB = 64
    TA = 32768
    TKEY = 249
    TLSA = 52
    TSIG = 250
    TXT = 16
    URI = 256
    ZONEMD = 63
    
    UNKNOWN = 0
    
    @classmethod
    def parse(cls, value: int) -> "DNSQueryType":
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


@dataclass
class DNSFlags:
    # Ref: https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
    QR: int  # 1 bit
    opcode: int  # 4 bits
    AA: int  # 1 bit
    TC: int  # 1 bit
    RD: int  # 1 bit
    RA: int  # 1 bit
    Z: int  # 1 bit
    AD: int  # 1 bit
    CD: int  # 1 bit
    rcode: int  # 4 bits

    @classmethod
    def parse(cls, raw: bytes) -> "DNSFlags":
        if len(raw) != 2:
            raise ValueError("DNS flags must be 2 bytes long.")
        flags_int = struct.unpack("!H", raw)[0]
        return cls(
            QR=(flags_int >> 15) & 0x1,
            opcode=(flags_int >> 11) & 0xF,
            AA=(flags_int >> 10) & 0x1,
            TC=(flags_int >> 9) & 0x1,
            RD=(flags_int >> 8) & 0x1,
            RA=(flags_int >> 7) & 0x1,
            Z=(flags_int >> 6) & 0x1,
            AD=(flags_int >> 5) & 0x1,
            CD=(flags_int >> 4) & 0x1,
            rcode=flags_int & 0xF,
        )


@dataclass
class DNSQuestion:
    target_name: str
    qtype: DNSQueryType
    qclass: int
    
@dataclass
class DNSRecord:
    name: str
    rtype: DNSQueryType
    rclass: int
    ttl: int
    rdata: bytes
    



@dataclass
class DNSPacket:
    # Ref: https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
    transaction_id: int  # 16 bits
    flags: DNSFlags  # 16 bits
    questions_count: int  # 16 bits
    answers_count: int  # 16 bits
    authority_rrs_count: int  # 16 bits
    additional_rrs_count: int  # 16 bits

    questions: List[DNSQuestion]
    answers: List[DNSRecord]

    @classmethod
    def parse(cls, raw: bytes) -> "DNSPacket":
        if len(raw) < 12:
            raise PacketLengthNotSatisfiedError(
                f"DNS packet must be at least 12 bytes long, got {len(raw)} bytes."
            )
        transaction_id, flag_raw, questions, answers, authority_rrs, additional_rrs = (
            struct.unpack("!HHHHHH", raw[:12])
        )
        flags = DNSFlags.parse(flag_raw)
        idx = 12
        
    def _get_name(self, raw: bytes, idx: int) -> Tuple[bytes, int]:
        name_parts = []
        cursor = idx
        processed_idx = -1
        jumped = False
        while True:
            if cursor >= len(raw):
                raise CursorOutOfBoundsError(
                    f"Cursor went out of bounds while parsing DNS name at index {cursor}."
                )
            length = raw[cursor]
            if length & 0xC0 == 0xC0:
                if not jumped:
                    nonlocal processed_idx
                    processed_idx = cursor + 2
                pointer = struct.unpack("!H", raw[cursor:cursor+2])[0]
                cursor = pointer & 0x3FFF
                jumped = True
                continue
            cursor += 1
            if length == 0:
                break
            
            name_parts.append(raw[cursor:cursor+length].decode("ascii", errors="replace"))
            cursor += length
        next_idx = processed_idx if jumped else cursor
        return ".".join(name_parts).encode("ascii"), next_idx
            
