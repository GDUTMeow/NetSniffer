import os
import json
import base64
import zlib
import time
from typing import Any, Dict, List
from collections import deque
from pathlib import Path

from logger import get_logger

logger = get_logger(__name__)


class PacketManager:
    def __init__(
        self, filename: str, directory: str = 'captures', max_packets: int = 100
    ):
        self._ensure_file_directory(directory)
        self.filename = filename
        self.directory = directory
        self.max_packets = max_packets
        self.cache: deque[Dict[str, Any]] = deque(maxlen=max_packets)  # 缓存
        self.offset_map: Dict[int, int] = {}  # idx -> file offset
        self.file_handle = open(
            f'{directory}/{filename}', 'a+', encoding='utf-8', buffering=1
        )
        self.packet_count = 0  # 记录所有包的数量

    def _ensure_file_directory(self, directory: Path):
        if not os.path.exists(directory):
            os.makedirs(directory)

    def load_range(self, start_idx: int, count: int = 50) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        # Load from cache
        if self.cache and start_idx >= self.cache[0]['idx']:
            for packet in self.cache:
                if packet['idx'] >= start_idx:
                    results.append(packet)
                    if len(results) >= count:
                        return results
        # Cache not enough
        remaining_count = count - len(results)
        # Load from file
        offset = self.offset_map.get(start_idx)

        if offset is not None:
            try:
                with open(
                    f'{self.directory}/{self.filename}', 'r', encoding='utf-8'
                ) as f:
                    f.seek(offset)
                    for _ in range(remaining_count):
                        line = f.readline()
                        if not line:
                            break

                        try:
                            data = json.loads(
                                zlib.decompress(base64.b64decode(line.strip())).decode(
                                    'utf-8'
                                )
                            )
                            results.append(data)
                        except (json.JSONDecodeError, zlib.error, Exception) as e:
                            logger.error(
                                f'Error decoding packet at idx {start_idx}: {e}'
                            )
                            continue
            except Exception as e:
                logger.error(f'File seek/read error: {e}')

        return results

    def save(self, idx: int, ts: float, length: int, label: str, raw: bytes) -> None:
        disk_data: Dict[str, Any] = {
            'idx': idx,
            'ts': ts,
            'len': length,
            'label': label,
            'raw': raw.hex(),
        }

        self.file_handle.flush()
        offset = self.file_handle.tell()
        self.offset_map[idx] = offset

        json_str = json.dumps(disk_data)
        compressed = zlib.compress(json_str.encode('utf-8'))
        b64_line = base64.b64encode(compressed).decode('utf-8')

        self.file_handle.write(b64_line + '\n')

    def add_packet(self, packet: Dict[str, Any], label: str) -> None:
        idx = self.packet_count
        ts = time.time()
        raw = packet.get('raw', b'')
        length = len(raw)

        packet.update({'idx': idx, 'ts': ts, 'len': length, 'label': label})
        self.cache.append(packet)
        self.packet_count += 1
        self.save(idx=idx, ts=ts, length=length, label=label, raw=raw)
