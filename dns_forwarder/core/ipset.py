from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_network
from pathlib import Path

import radix

IPSET_CONTEXT_KEY = "core.ipset"


def normalize_network(value: str) -> str:
    return ip_network(value.strip(), strict=False).with_prefixlen


class IPSet:
    def __init__(self, directory: str | None) -> None:
        network_to_tags: dict[str, str] = {}
        for tag, networks in _load_tag_files(directory, normalize_network).items():
            for network in networks:
                existing_tag = network_to_tags.get(network)
                if existing_tag is not None and existing_tag != tag:
                    raise ValueError(f"network 重复归属多个 tag: {network}")
                network_to_tags[network] = tag

        self._tree: radix.Radix | None
        if not network_to_tags:
            self._tree = None
            return

        tree = radix.Radix()
        for network, tag in sorted(network_to_tags.items()):
            node = tree.add(network)
            node.data["tag"] = tag
        self._tree = tree

    def lookup(self, address: str) -> set[str]:
        if self._tree is None:
            return set()

        tags: set[str] = set()
        search_target = ip_network(address, strict=False).with_prefixlen
        for node in self._tree.search_covering(search_target):
            tag = node.data.get("tag")
            if isinstance(tag, str):
                tags.add(tag)
        return tags


def _load_tag_files(
    directory: str | None,
    normalizer,
) -> dict[str, set[str]]:
    tag_to_values: dict[str, set[str]] = defaultdict(set)
    if directory is None:
        return tag_to_values

    path = Path(directory)
    if not path.exists():
        raise FileNotFoundError(f"tag 目录不存在: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"tag 路径不是目录: {path}")

    for file_path in sorted(path.iterdir(), key=lambda item: item.name):
        if not file_path.is_file() or file_path.name.startswith("."):
            continue
        tag = file_path.stem
        if not tag:
            continue
        for line in file_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            tag_to_values[tag].add(normalizer(stripped))

    return tag_to_values
