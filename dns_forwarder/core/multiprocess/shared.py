from __future__ import annotations

import shutil
import uuid
from dataclasses import dataclass
from multiprocessing import shared_memory
from pathlib import Path

from dns_forwarder.config import AppConfig

from ..domainset import DomainSet, DomainSetSnapshot
from ..ipset import IPSet


@dataclass(frozen=True, slots=True)
class SharedIPSetSnapshot:
    name: str
    size: int


@dataclass(slots=True)
class SharedTreeResources:
    domain_snapshot: DomainSetSnapshot
    ip_snapshot: SharedIPSetSnapshot
    ip_shared_memory: shared_memory.SharedMemory
    temp_dir: Path

    @classmethod
    def build(cls, config: AppConfig, base_dir: Path) -> "SharedTreeResources":
        temp_path = make_shared_temp_dir(base_dir)
        ip_shared_memory: shared_memory.SharedMemory | None = None

        try:
            domain_snapshot = DomainSet(config.tree_root.domain_dir).save_mmap(
                temp_path / "domainset.marisa"
            )
            ip_payload = IPSet(config.tree_root.ip_dir).to_snapshot().payload
            ip_shared_memory = shared_memory.SharedMemory(create=True, size=len(ip_payload))
            ip_shared_memory.buf[: len(ip_payload)] = ip_payload
        except Exception:
            if ip_shared_memory is not None:
                ip_shared_memory.close()
                try:
                    ip_shared_memory.unlink()
                except FileNotFoundError:
                    pass
            shutil.rmtree(temp_path, ignore_errors=True)
            raise
        return cls(
            domain_snapshot=domain_snapshot,
            ip_snapshot=SharedIPSetSnapshot(
                name=ip_shared_memory.name,
                size=len(ip_payload),
            ),
            ip_shared_memory=ip_shared_memory,
            temp_dir=temp_path,
        )

    def close(self) -> None:
        self.ip_shared_memory.close()
        try:
            self.ip_shared_memory.unlink()
        except FileNotFoundError:
            pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)


def make_shared_temp_dir(base_dir: Path) -> Path:
    candidates = (base_dir, Path.cwd())
    for parent in candidates:
        try:
            parent.mkdir(parents=True, exist_ok=True)
            temp_path = parent / f"python-smartdns-{uuid.uuid4().hex}"
            temp_path.mkdir()
            return temp_path
        except OSError:
            continue
    raise RuntimeError("无法创建共享数据临时目录")
