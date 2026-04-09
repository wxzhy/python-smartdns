from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import marisa_trie

DOMAINSET_CONTEXT_KEY = "core.domainset"


def normalize_domain(value: str) -> str:
    normalized = value.strip().rstrip(".").lower()
    if not normalized:
        raise ValueError("域名不能为空")
    return normalized


def reverse_domain(value: str) -> str:
    labels = reversed(normalize_domain(value).split("."))
    return ".".join(labels) + "."


class DomainSet:
    def __init__(self, directory: str | None) -> None:
        self._entries = self._build_domain_entries(directory)
        self._trie = (
            marisa_trie.StringTrie(
                self._entries
            )
            if self._entries
            else None
        )

    def lookup(self, qname: str) -> set[str]:
        if self._trie is None:
            return set()

        tags: set[str] = set()
        for _, tag in self._trie.prefix_items(reverse_domain(qname)):
            tags.add(tag)
        return tags

    @staticmethod
    def _build_domain_entries(directory: str | None) -> list[tuple[str, str]]:
        domain_to_tag: dict[str, str] = {}
        for tag, domains in _load_tag_files(directory, normalize_domain).items():
            for domain in domains:
                reversed_domain = reverse_domain(domain)
                existing_tag = domain_to_tag.get(reversed_domain)
                if existing_tag is not None and existing_tag != tag:
                    raise ValueError(f"domain 重复归属多个 tag: {domain}")
                domain_to_tag[reversed_domain] = tag
        return sorted(domain_to_tag.items())


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

    for file_path in sorted(path.glob("*.txt")):
        if not file_path.is_file():
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
