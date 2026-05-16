import struct
import socket
from dataclasses import dataclass, field
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
    def parse(cls, value: int) -> 'DNSQueryType':
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
    def parse(cls, raw: bytes) -> 'DNSFlags':
        if len(raw) != 2:
            raise PacketLengthNotSatisfiedError('DNS flags must be 2 bytes long.')
        flags_int = struct.unpack('!H', raw)[0]
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
    rdata: bytes | str


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
    authorities: List[DNSRecord] = field(default_factory=list)  # type: ignore
    additionals: List[DNSRecord] = field(default_factory=list)  # type: ignore

    @classmethod
    def parse(cls, raw: bytes) -> 'DNSPacket':
        # Ref: https://github.com/hibikiF/rfc1035/blob/master/src/rfc1035.c
        if len(raw) < 12:
            raise PacketLengthNotSatisfiedError(
                f'DNS packet too short: {len(raw)} bytes.'
            )

        (transaction_id, flag_raw, q_count, a_count, auth_count, add_count) = (
            struct.unpack('!HHHHHH', raw[:12])
        )
        flags = DNSFlags.parse(flag_raw.to_bytes(2, 'big'))

        idx = 12

        def parse_rr(current_idx: int, count: int) -> Tuple[List[DNSRecord], int]:
            records: List[DNSRecord] = []
            ptr = current_idx
            for _ in range(count):
                name, ptr = cls._get_name(raw, ptr)
                if ptr + 10 > len(raw):
                    break

                rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', raw[ptr : ptr + 10])
                ptr += 10

                rdata_raw = raw[ptr : ptr + rdlen]
                rtype_enum = DNSQueryType.parse(rtype)

                if rtype_enum == DNSQueryType.A and rdlen == 4:
                    parsed_val = socket.inet_ntoa(rdata_raw)
                elif rtype_enum == DNSQueryType.AAAA and rdlen == 16:
                    parsed_val = socket.inet_ntop(socket.AF_INET6, rdata_raw)
                elif rtype_enum in (
                    DNSQueryType.CNAME,
                    DNSQueryType.NS,
                    DNSQueryType.PTR,
                ):
                    parsed_val, _ = cls._get_name(raw, ptr)
                else:
                    parsed_val = rdata_raw

                records.append(DNSRecord(name, rtype_enum, rclass, ttl, parsed_val))
                ptr += rdlen
            return records, ptr

        questions: List[DNSQuestion] = []
        for _ in range(q_count):
            qname, idx = cls._get_name(raw, idx)
            qtype, qclass = struct.unpack('!HH', raw[idx : idx + 4])
            idx += 4
            questions.append(DNSQuestion(qname, DNSQueryType.parse(qtype), qclass)) # type: ignore

        answers, idx = parse_rr(idx, a_count)
        authorities, idx = parse_rr(idx, auth_count)
        additionals, idx = parse_rr(idx, add_count)

        return cls(
            transaction_id=transaction_id,
            flags=flags,
            questions_count=q_count,
            answers_count=a_count,
            authority_rrs_count=auth_count,
            additional_rrs_count=add_count,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
        )

    @classmethod
    def _get_name(cls, raw: bytes, offset: int) -> Tuple[str, int]:
        parts: List[str] = []
        current: int = offset
        jumped: bool = False
        jump_target: int = -1

        while True:
            if current >= len(raw):
                raise CursorOutOfBoundsError(f'Cursor out of bounds at {current}')

            length = raw[current]
            # compressed
            if length & 0xC0 == 0xC0:
                if current + 1 >= len(raw):
                    raise CursorOutOfBoundsError('Truncated pointer in DNS name')
                # record the position after jump for later use
                if not jumped:
                    jump_target = current + 2
                # calculate the pointer target
                pointer = struct.unpack('!H', raw[current : current + 2])[0] & 0x3FFF
                current = pointer
                jumped = True
                continue

            # normal label
            current += 1
            if length == 0:
                break

            if current + length > len(raw):
                raise CursorOutOfBoundsError('DNS label exceeds packet boundary')
            label: str = raw[current : current + length].decode(
                'ascii', errors='replace'
            )
            parts.append(label)
            current += length

        # Jumped, so need to return
        next_idx = jump_target if jumped else current
        return '.'.join(parts), next_idx
