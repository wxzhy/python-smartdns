from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import marisa_trie

DOMAINSET_CONTEXT_KEY = "core.domainset"
TAG_SEPARATOR = "\0"


@dataclass(frozen=True, slots=True)
class DomainSetSnapshot:
    mmap_path: str | None


def normalize_domain(value: str) -> str:
    normalized = value.strip().rstrip(".").lower()
    if normalized.startswith("+."):
        normalized = normalized[2:]
    if not normalized:
        raise ValueError("域名不能为空")
    return normalized


def reverse_domain(value: str) -> str:
    labels = reversed(normalize_domain(value).split("."))
    return ".".join(labels) + "."


class DomainSet:
    def __init__(self, directory: str | None, *, mmap_path: str | None = None) -> None:
        self._trie: marisa_trie.BytesTrie | None
        if mmap_path is not None:
            self._trie = marisa_trie.BytesTrie().mmap(mmap_path)
            return

        domain_to_tags = self._build_domain_entries(directory)
        self._trie = (
            marisa_trie.BytesTrie(
                (domain, _encode_tags(tags)) for domain, tags in domain_to_tags.items()
            )
            if domain_to_tags
            else None
        )

    def lookup(self, qname: str) -> set[str]:
        if self._trie is None:
            return set()

        tags: set[str] = set()
        for matched_domain in self._trie.prefixes(reverse_domain(qname)):
            for value in self._trie[matched_domain]:
                tags.update(_decode_tags(value))
        return tags

    def save_mmap(self, path: str | Path) -> DomainSetSnapshot:
        if self._trie is None:
            return DomainSetSnapshot(mmap_path=None)
        mmap_path = Path(path)
        mmap_path.parent.mkdir(parents=True, exist_ok=True)
        self._trie.save(str(mmap_path))
        return DomainSetSnapshot(mmap_path=str(mmap_path))

    @classmethod
    def from_snapshot(cls, snapshot: DomainSetSnapshot) -> "DomainSet":
        return cls(None, mmap_path=snapshot.mmap_path) if snapshot.mmap_path else cls(None)

    @staticmethod
    def _build_domain_entries(directory: str | None) -> dict[str, frozenset[str]]:
        domain_to_tags: dict[str, set[str]] = defaultdict(set)
        for tag, domains in _load_tag_files(directory, normalize_domain).items():
            for domain in domains:
                reversed_domain = reverse_domain(domain)
                domain_to_tags[reversed_domain].add(tag)
        return {domain: frozenset(tags) for domain, tags in sorted(domain_to_tags.items())}


def _encode_tags(tags: frozenset[str]) -> bytes:
    return TAG_SEPARATOR.join(sorted(tags)).encode("utf-8")


def _decode_tags(value: bytes) -> set[str]:
    return {tag for tag in value.decode("utf-8").split(TAG_SEPARATOR) if tag}


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
