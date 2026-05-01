from __future__ import annotations

from ._trick_tcp import TrickyStreamSocket
from ._trick_udp import TrickyDatagramSocket

__all__ = ["TrickyDatagramSocket", "TrickyStreamSocket"]
