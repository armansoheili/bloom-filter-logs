#!/usr/bin/env python3
"""Ethereum-style log bloom filters in pure Python (zero dependencies).

An Ethereum block header carries a 2048-bit bloom filter over all event logs
in the block. Light clients use it to quickly rule OUT blocks that cannot
contain logs of interest: a negative answer is always correct, a positive one
is "maybe" and needs a full check.

For each address and each topic, 3 bits are set out of 2048:
    bit = low 11 bits of keccak256(item)[i]  for i in (1, 3, 5)
(the standard Yellow Paper scheme).

Usage:
    python3 bloom_filter.py
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Self-contained Keccak-256 (Keccak-f[1600], 1088-bit rate, 0x01 suffix).
# ---------------------------------------------------------------------------
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROTATION_OFFSETS = (  # indexed [y][x] = r[x][y]
    (0, 1, 62, 28, 27),
    (36, 44, 6, 55, 20),
    (3, 10, 43, 25, 39),
    (41, 45, 15, 21, 8),
    (18, 2, 61, 56, 14),
)
_MASK = (1 << 64) - 1


def _keccak_f1600(state: list[int]) -> None:
    for rc in _ROUND_CONSTANTS:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(
                    state[x + 5 * y], _ROTATION_OFFSETS[y][x])
        # chi + iota
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (b[x + 5 * y]
                                    ^ ((~b[(x + 1) % 5 + 5 * y] & _MASK)
                                       & b[(x + 2) % 5 + 5 * y])) & _MASK
        state[0] ^= rc


def _rotl(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _MASK if n else x & _MASK


def keccak256(data: bytes) -> bytes:
    """Keccak-256 hash of bytes (Ethereum's hash function)."""
    rate = 136  # bytes per block (1088 bits)
    state = [0] * 25
    padded = bytearray(data) + b"\x01"
    # pad10*1: zeros, then a final byte with the high bit set; the padding
    # always ends on a block boundary (a full extra block if needed).
    n = rate - (len(padded) % rate)  # bytes to add, including the 0x80 byte
    padded += b"\x00" * (n - 1)
    padded += b"\x80"
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(len(block) // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f1600(state)
    return b"".join(w.to_bytes(8, "little") for w in state[:4])


# ---------------------------------------------------------------------------
# 2048-bit bloom filter (Ethereum log-bloom scheme).
# ---------------------------------------------------------------------------
M = 2048  # filter size in bits


class LogBloom:
    """Ethereum-style 2048-bit bloom filter over log entries."""

    def __init__(self, bits: int = 0) -> None:
        self.bits = bits  # stored as a Python int bitfield

    @staticmethod
    def _item_bits(item: bytes) -> list[int]:
        h = keccak256(item)
        return [
            int.from_bytes(h[1:3], "big") & (M - 1),
            int.from_bytes(h[3:5], "big") & (M - 1),
            int.from_bytes(h[5:7], "big") & (M - 1),
        ]

    def add(self, item: bytes) -> None:
        """Add an address or topic (bytes) to the filter."""
        for b in self._item_bits(item):
            self.bits |= 1 << b

    def contains(self, item: bytes) -> bool:
        """True = maybe present. False = definitely NOT present."""
        return all(self.bits & (1 << b) for b in self._item_bits(item))

    def add_log(self, address: bytes, topics: list[bytes]) -> None:
        for item in (address, *topics):
            self.add(item)

    def matches_log(self, address: bytes | None,
                    topics: list[bytes | None]) -> bool:
        """Filter-query: address/topics are None when the query is a wildcard."""
        if address is not None and not self.contains(address):
            return False
        return all(t is None or self.contains(t) for t in topics)

    def __or__(self, other: "LogBloom") -> "LogBloom":
        return LogBloom(self.bits | other.bits)

    def popcount(self) -> int:
        return bin(self.bits).count("1")

    def to_bytes(self) -> bytes:
        return self.bits.to_bytes(M // 8, "big")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "LogBloom":
        assert len(raw) == M // 8, "bloom must be 256 bytes"
        return cls(int.from_bytes(raw, "big"))


def demo() -> None:
    print("Ethereum log bloom filter demo (2048-bit)")
    print("-" * 48)

    # Three fake contract addresses and an ERC-20 Transfer topic.
    addr = lambda n: bytes([n]) * 20                       # 20-byte address
    topic = keccak256(b"Transfer(address,address,uint256)")

    token_a, token_b = addr(0xA0), addr(0xB0)
    block_bloom = LogBloom()
    block_bloom.add_log(token_a, [topic])                   # block has 1 log
    print(f"bits set in block bloom: {block_bloom.popcount()} / {M}")

    # 1) Exact log -> "maybe present" (true positive).
    print("contains token_a + Transfer topic:",
          block_bloom.matches_log(token_a, [topic]))

    # 2) Address never logged -> definitely absent (true negative).
    print("contains token_b (not in block):",
          block_bloom.matches_log(token_b, [None]))

    # 3) Block-header style OR-aggregation of per-tx blooms.
    tx1, tx2 = LogBloom(), LogBloom()
    tx1.add_log(token_a, [topic])
    tx2.add_log(token_b, [])
    header_bloom = tx1 | tx2
    print("header bloom matches token_b:",
          header_bloom.matches_log(token_b, [None]))
    print("header bloom serialization round-trip:",
          LogBloom.from_bytes(header_bloom.to_bytes()).bits
          == header_bloom.bits)

    # 4) Wildcard query (any Transfer anywhere).
    print("any Transfer in block:", block_bloom.matches_log(None, [topic]))


if __name__ == "__main__":
    demo()
