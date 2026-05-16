import struct
from dataclasses import dataclass
from typing import Literal

from exception import PacketLengthNotSatisfiedError


@dataclass
class NTPFlags:
    leap_indicator: int  # 2 bits
    version_number: int  # 3 bits
    mode: Literal["server", "client", "unknown"]  # 3 bits

    @classmethod
    def parse(cls, flags: int) -> "NTPFlags":
        leap_indicator = (flags >> 6) & 0b11
        version_number = (flags >> 3) & 0b111
        mode = flags & 0b111
        if mode == 4:
            mode_str = "server"
        elif mode == 3:
            mode_str = "client"
        else:
            mode_str = "unknown"
        return cls(
            leap_indicator=leap_indicator,
            version_number=version_number,
            mode=mode_str,
        )


@dataclass
class NTPPacket:
    flags: NTPFlags  # 8 bits
    pcs: int  # 8 bits, Peer Clock Stratum
    ppi: int  # 8 bits, Peer Poll Interval
    pcp: int  # 8 bits, Peer Clock Precision
    root_delay: float  # 32 bits, Root Delay
    root_dispersion: float  # 32 bits, Root Dispersion
    ref_id: int | str  # 32 bits, Reference ID
    ref_ts: float  # 64 bits, Reference Timestamp
    orig_ts: float  # 64 bits, Originate Timestamp
    recv_ts: float  # 64 bits, Receive Timestamp
    transmit_ts: float  # 64 bits, Transmit Timestamp

    @classmethod
    def parse(cls, raw: bytes) -> "NTPPacket":
        if len(raw) != 48:
            raise PacketLengthNotSatisfiedError(
                f"NTP packet must be 48 bytes, got {len(raw)} bytes"
            )
        (
            flags,
            pcs,
            ppi,
            pcp,
            root_delay,
            root_dispersion,
            ref_id,
            ref_ts,
            orig_ts,
            recv_ts,
            transmit_ts,
        ) = struct.unpack("!BBBBII4sQQQQ", raw)
        # Trying to convert ref_id to ip addr
        try:
            addr_tmp = struct.unpack("!BBBB", ref_id)
            ref_id = ".".join(map(str, addr_tmp))
        except Exception:
            pass
        return cls(
            flags=NTPFlags.parse(flags),
            pcs=pcs,
            ppi=ppi,
            pcp=pcp,
            root_delay=root_delay,
            root_dispersion=root_dispersion,
            ref_id=ref_id,
            ref_ts=cls._to_unix_timestamp(ref_ts),
            orig_ts=cls._to_unix_timestamp(orig_ts),
            recv_ts=cls._to_unix_timestamp(recv_ts),
            transmit_ts=cls._to_unix_timestamp(transmit_ts),
        )

    @classmethod
    def _to_unix_timestamp(cls, ntp_raw: int) -> float:
        if ntp_raw == 0:
            return 0.0
        # Seconds from 1900-01-01 00:00:00 UTC
        seconds = ntp_raw >> 32
        # Fractional part, converted to seconds
        fraction = (ntp_raw & 0xFFFFFFFF) / 2**32
        # Convert to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
        return seconds - 2208988800 + fraction


if __name__ == "__main__":
    PACKETS = [
        "23000000000000000000000000000000000000000000000000000000000000000000000000000000edb2cdfe3d6af038",
        "240100e7000000010000000142445300edb2cdfcd3381c3fedb2cdfe3d6af038edb2cdfe57284481edb2cdfe572a7098",
        "23000000000000000000000000000000000000000000000000000000000000000000000000000000edb2cdfe4bf4dbdf",
        "240203e90000001800000808647a24c4edb2c9de512b9a42edb2cdfe4bf4dbdfedb2cdfe5f2df0dfedb2cdfe5f2fb0dd",
        "23000000000000000000000000000000000000000000000000000000000000000000000000000000edb2cdfe501cd5f9",
        "240300e6000001b2000000247f000001edb2cdd5ee3e1216edb2cdfe501cd5f9edb2cdfe78ab3207edb2cdfe78ac64e0",
        "23000000000000000000000000000000000000000000000000000000000000000000000000000000edb2cdfe821bd1ed",
        "240300e6000001b20000002d7f000001edb2cdccf7feda99edb2cdfe821bd1ededb2cdfeaac86ac9edb2cdfeaac8e96e",
        "23000000000000000000000000000000000000000000000000000000000000000000000000000000edb2cdfeaca52695",
        "240300e600000905000000300aff0804edb2cdd1bde1b675edb2cdfeaca52695edb2cdfed394ed71edb2cdfed39881ee"
    ]
    for packet in PACKETS:
        raw = bytes.fromhex(packet)
        ntp_packet = NTPPacket.parse(raw)
        print(ntp_packet)
