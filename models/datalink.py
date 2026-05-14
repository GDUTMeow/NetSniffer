# Data Link Layer
import struct
from dataclasses import dataclass
from enum import Enum


class EtherType(Enum):
    # Ref: https://support.huawei.com/enterprise/zh/doc/EDOC1100174722/ea0a043c
    IPV4 = 0x0800  # Internet Protocol Version 4
    X75 = 0x0801  # X.75 Internet
    X25L3 = 0x0805  # X.25 Level 3
    ARP = 0x0806  # Address Resolution Protocol
    FRARP = 0x0808  # Frame Relay ARP
    TRILL = 0x22F3  # TRILL
    L2ISIS = 0x22F4  # Layer 2 IS-IS
    TEB = 0x6558  # Transparent Ethernet Bridging
    RFR = 0x6559  # Raw Frame Relay
    RARP = 0x8035  # Reverse Address Resolution Protocol
    AppleTalk = 0x809B  # AppleTalk
    STD8021 = 0x8100  # IEEE 802.1Q VLAN tagging
    NNWISPX = 0x8137  # Novell NetWare IPX/SPX
    Novell = 0x8138  # Novell
    SNMPoE = 0x814C # SNMP over Ethernet
    IPV6 = 0x86DD  # Internet Protocol Version 6
    TCPCompression = 0x876B  # TCP/IP Compression
    IPAS = 0x876C  # IP Autonomous Systems
    SecureData = 0x876D  # Secure Data
    EPON = 0x8808  # IEEE Std 802.3 Ethernet Passive Optical Network
    PPP = 0x880B  # Point-to-Point Protocol
    GSMP = 0x880C  # General Switch Management Protocol
    MPLS = 0x8847  # MPLS (multiprotocol label switching)
    MPLSWL = 0x8848  # MPLS with upstream-assigned labels
    PPPoeDiscovery = 0x8863  # PPPoE Discovery Stage
    PPPoESession = 0x8864  # PPPoE Session Stage
    PNAC = 0x888E  # Port-based Network Access Control (IEEE 802.1X)
    SVLAN = 0x88A8  # Service VLAN tag identifier (S-Tag)
    OUIEE = 0x88B7  # OUI Extended Ethertype (IEEE 802)
    PreAuth = 0x88C7    # Pre-Authentication (IEEE 802.11i)
    LLDP = 0x88CC  # Link Layer Discovery Protocol
    MACS = 0x88E5  # Media Access Control Security (IEEE 802.1AE)
    MVRP = 0x88F5  # Multiple VLAN Registration Protocol (IEEE 802.1Q)
    MMRP = 0x88F6  # Multiple Multicast Registration Protocol (IEEE 802.1Q)
    FGP = 0x893B    # TRILL Fine Grained Labeling (FGL)
    TRBC = 0x8946   # TRILL RBridge Channel

@dataclass
class EthernetFrame:  # 以太网数据帧
    dst_mac: str
    src_mac: str
    ethertype: EtherType
    payload: bytes
