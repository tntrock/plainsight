"""Minimal TCP stream reassembly: turns segments into an ordered byte stream."""
from __future__ import annotations

MASK = 0xFFFFFFFF
HALF = 0x80000000


class DirectionReassembler:
    """Reassembles one direction of a TCP connection.

    Handles out-of-order segments and retransmissions. If too many segments
    are waiting for a gap that never fills (packet loss in the capture), the
    gap is skipped so analysis can continue.
    """

    MAX_PENDING = 128

    def __init__(self) -> None:
        self.next_seq: int | None = None
        self.pending: dict[int, bytes] = {}

    def syn(self, seq: int) -> None:
        self.next_seq = (seq + 1) & MASK
        self.pending.clear()

    def feed(self, seq: int, payload: bytes) -> bytes:
        if not payload:
            return b""
        if self.next_seq is None:
            self.next_seq = seq
        out = bytearray()
        diff = (seq - self.next_seq) & MASK
        if diff and diff < HALF:  # arrives ahead of a gap
            self.pending.setdefault(seq, payload)
            if len(self.pending) > self.MAX_PENDING:
                self.next_seq = min(self.pending, key=lambda s: (s - self.next_seq) & MASK)
                self._drain(out)
            return bytes(out)
        if diff:  # retransmission, possibly with some new data at the end
            back = (self.next_seq - seq) & MASK
            if back >= len(payload):
                return b""
            payload = payload[back:]
        out += payload
        self.next_seq = (self.next_seq + len(payload)) & MASK
        self._drain(out)
        return bytes(out)

    def _drain(self, out: bytearray) -> None:
        progressed = True
        while progressed and self.pending:
            progressed = False
            for s in list(self.pending):
                diff = (s - self.next_seq) & MASK
                if diff and diff < HALF:
                    continue
                data = self.pending.pop(s)
                back = (self.next_seq - s) & MASK if diff else 0
                if back < len(data):
                    out += data[back:]
                    self.next_seq = (self.next_seq + len(data) - back) & MASK
                progressed = True
