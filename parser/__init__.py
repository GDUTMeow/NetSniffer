from models.datalink import EthernetFrame


class Parser:
    def __init__(self):
        pass

    def parse_ethernet(self, raw_data: bytes, protocol: str) -> EthernetFrame:
        print(
            f'Parsing Ethernet frame from raw data: {raw_data.hex()}: {EthernetFrame.parse(raw_data)}'
        )
        return EthernetFrame.parse(raw_data)
