# Data Link Layer
import struct
from dataclasses import dataclass
from enum import Enum


class EtherType(Enum):
    # Ref: https://support.huawei.com/enterprise/zh/doc/EDOC1100174722/ea0a043c
    # https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
    # IPv4 & IPv6
    IPV4 = 0x0800  # Internet Protocol Version 4
    IPV6 = 0x86DD  # Internet Protocol Version 6

    # Address Resolution
    ARP = 0x0806  # Address Resolution Protocol
    RARP = 0x8035  # Reverse Address Resolution Protocol
    FR_ARP = 0x0808  # Frame Relay ARP

    # Virtual LANs (VLAN)
    VLAN_TAG = 0x8100  # IEEE 802.1Q VLAN tagging
    S_VLAN = 0x88A8  # Service VLAN tag identifier (S-Tag)

    # Novell & Legacy Systems
    IPX_SPX = 0x8137  # Novell NetWare IPX/SPX
    NOVELL = 0x8138  # Novell
    APPLE_TALK = 0x809B  # AppleTalk

    # Point-to-Point Protocol
    PPP = 0x880B  # Point-to-Point Protocol
    PPPOE_DISCOVERY = 0x8863  # PPPoE Discovery Stage
    PPPOE_SESSION = 0x8864  # PPPoE Session Stage

    # MPLS
    MPLS = 0x8847  # MPLS (multiprotocol label switching)
    MPLS_WL = 0x8848  # MPLS with upstream-assigned labels

    # Link Layer & Control
    LLDP = 0x88CC  # Link Layer Discovery Protocol
    L2_ISIS = 0x22F4  # Layer 2 IS-IS
    PNAC = 0x888E  # Port-based Network Access Control (IEEE 802.1X)
    GSMP = 0x880C  # General Switch Management Protocol

    # TRILL
    TRILL = 0x22F3  # TRILL
    TRILL_FGL = 0x893B  # TRILL Fine Grained Labeling (FGL)
    TRILL_RBRIDGE = 0x8946  # TRILL RBridge Channel

    # Others
    X75 = 0x0801  # X.75 Internet
    X25_L3 = 0x0805  # X.25 Level 3
    TEB = 0x6558  # Transparent Ethernet Bridging
    RFR = 0x6559  # Raw Frame Relay
    SNMP_OE = 0x814C  # SNMP over Ethernet
    TCP_COMPRESSION = 0x876B  # TCP/IP Compression
    IP_AS = 0x876C  # IP Autonomous Systems
    SECURE_DATA = 0x876D  # Secure Data
    EPON = 0x8808  # IEEE Std 802.3 Ethernet Passive Optical Network
    OUI_EXTENDED = 0x88B7  # OUI Extended Ethertype (IEEE 802)
    PRE_AUTH = 0x88C7  # Pre-Authentication (IEEE 802.11i)
    MAC_SEC = 0x88E5  # Media Access Control Security (IEEE 802.1AE)
    MVRP = 0x88F5  # Multiple VLAN Registration Protocol (IEEE 802.1Q)
    MMRP = 0x88F6  # Multiple Multicast Registration Protocol (IEEE 802.1Q)

    @classmethod
    def query(cls, value: int) -> str:
        try:
            return cls(value).name
        except ValueError:
            return f"Unknown (0x{value:04X})"


@dataclass
class EthernetFrame:  # 以太网数据帧
    # Linux only，Windows 和 MacOS 会自己把以太网头给扔掉，导致这里没办法获取到
    # 没办法在课设的情况下去调用 BPF 和 Npcap，所以没办法在这个地方给这两个系统提供这种能力，以后再说吧，想搞了再搞
    dst_mac: str
    src_mac: str
    ethertype: EtherType
    payload: bytes

    @staticmethod
    def macaddr(raw: bytes) -> str:
        return ":".join(f"{b:02x}" for b in raw)
    
    @classmethod
    def parse(cls, raw_data: bytes) -> "EthernetFrame":
        dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw_data[:14])
        return cls(
            dst_mac=cls.macaddr(dst_mac),
            src_mac=cls.macaddr(src_mac),
            ethertype=EtherType(ethertype) if ethertype in EtherType._value2member_map_ else EtherType(0xFFFF),
            payload=raw_data[14:],
        )