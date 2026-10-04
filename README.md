# bloom-filter-logs

Ethereum-style 2048-bit log bloom filters in **pure Python** — zero dependencies.

An Ethereum block header embeds a 2048-bit bloom filter over all event logs in
the block. Light clients use it to quickly rule *out* blocks that cannot
contain logs of interest: a negative answer is always correct, a positive one
is "maybe" and needs a full check.

## How it works

For each address and topic, 3 bits out of 2048 are set:

```
bit_i = low 11 bits of keccak256(item)[i]   for i in (1, 3, 5)
```

This is the exact scheme from the Ethereum Yellow Paper, implemented with a
self-contained Keccak-256 sponge (no libraries).

## Run

```bash
python3 bloom_filter.py
```

## Demo output highlights

- Exact log queried → "maybe present" (true positive)
- Address never logged → definitely absent (true negative)
- Per-transaction blooms OR-ed together like a real block header
- Wildcard queries (any `Transfer` in the block)
- 256-byte serialization round-trip

## Files

- `bloom_filter.py` — Keccak-256 + `LogBloom` class + runnable demo
