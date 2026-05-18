from __future__ import annotations

import pickle
from collections import defaultdict
from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

import radix
from radix.radix import Radix as PurePythonRadix

IPSET_CONTEXT_KEY = "core.ipset"


@dataclass(frozen=True, slots=True)
class IPSetSnapshot:
    payload: bytes


def normalize_network(value: str) -> str:
    return ip_network(value.strip(), strict=False).with_prefixlen


class IPSet:
    def __init__(self, directory: str | None, *, tree: Any | None = None) -> None:
        self._network_to_tags: dict[str, frozenset[str]] = {}
        if tree is not None:
            self._tree = tree
            return

        network_to_tags: dict[str, set[str]] = defaultdict(set)
        for tag, networks in _load_tag_files(directory, normalize_network).items():
            for network in networks:
                network_to_tags[network].add(tag)

        self._tree: Any | None
        if not network_to_tags:
            self._tree = None
            return

        self._network_to_tags = {
            network: frozenset(tags)
            for network, tags in sorted(network_to_tags.items())
        }
        self._tree = _build_radix_tree(self._network_to_tags)

    def lookup(self, address: str) -> set[str]:
        if self._tree is None:
            return set()

        tags: set[str] = set()
        search_target = ip_network(address, strict=False).with_prefixlen
        for node in self._tree.search_covering(search_target):
            node_tags = node.data.get("tags")
            if isinstance(node_tags, (set, frozenset, list, tuple)):
                tags.update(tag for tag in node_tags if isinstance(tag, str))
        return tags

    def to_snapshot(self) -> IPSetSnapshot:
        try:
            payload = pickle.dumps(self._tree)
        except (AttributeError, TypeError, pickle.PicklingError):
            payload = pickle.dumps(
                _build_radix_tree(self._network_to_tags, prefer_native=False)
            )
        return IPSetSnapshot(payload=payload)

    @classmethod
    def from_snapshot(cls, snapshot: IPSetSnapshot) -> "IPSet":
        tree = pickle.loads(snapshot.payload)
        return cls(None, tree=tree)


def _build_radix_tree(
    network_to_tags: dict[str, frozenset[str]],
    *,
    prefer_native: bool = True,
) -> Any:
    tree = _new_radix_tree(prefer_native=prefer_native)
    for network, tags in network_to_tags.items():
        node = tree.add(network)
        node.data["tags"] = tags
    return tree


def _new_radix_tree(*, prefer_native: bool = True) -> Any:
    if prefer_native:
        tree = radix.Radix()
        try:
            tree.add("0.0.0.0/32")
            tree.delete("0.0.0.0/32")
            return tree
        except UnicodeDecodeError:
            pass
    return PurePythonRadix()


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
