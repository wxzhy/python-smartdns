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
        self._domain_to_tags = self._build_domain_entries(directory)
        self._trie = marisa_trie.Trie(self._domain_to_tags) if self._domain_to_tags else None

    def lookup(self, qname: str) -> set[str]:
        if self._trie is None:
            return set()

        tags: set[str] = set()
        for matched_domain in self._trie.prefixes(reverse_domain(qname)):
            tags.update(self._domain_to_tags.get(matched_domain, ()))
        return tags

    @staticmethod
    def _build_domain_entries(directory: str | None) -> dict[str, frozenset[str]]:
        domain_to_tags: dict[str, set[str]] = defaultdict(set)
        for tag, domains in _load_tag_files(directory, normalize_domain).items():
            for domain in domains:
                reversed_domain = reverse_domain(domain)
                domain_to_tags[reversed_domain].add(tag)
        return {
            domain: frozenset(tags)
            for domain, tags in sorted(domain_to_tags.items())
        }


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
