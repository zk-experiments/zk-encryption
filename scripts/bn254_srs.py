#!/usr/bin/env python3
"""Expands bb's compressed BN254 G1 points into bn254_g1.dat.

Compressed (bb's g1_compressed.dat): 32 bytes per point, x big-endian with
the top bit set when y is odd. Expanded (bn254_g1.dat): 64 bytes, x || y,
big-endian. noir-zk checks the result against its pinned SHA-256.

    bn254_srs.py <compressed> <out> <points>
"""
import sys

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
SQRT = (P + 1) // 4  # P = 3 (mod 4)


def expand(src, dst, points):
    data = open(src, "rb").read(points * 32)
    if len(data) != points * 32:
        sys.exit(f"{src}: {len(data)} bytes, need {points * 32}")
    out = bytearray()
    for i in range(points):
        v = int.from_bytes(data[32 * i : 32 * i + 32], "big")
        odd, x = v >> 255, v & ((1 << 255) - 1)
        rhs = (x * x * x + 3) % P
        y = pow(rhs, SQRT, P)
        if y * y % P != rhs:
            sys.exit(f"point {i}: x is not on BN254")
        if y & 1 != odd:
            y = P - y
        out += x.to_bytes(32, "big") + y.to_bytes(32, "big")
    with open(dst, "wb") as f:
        f.write(out)


if __name__ == "__main__":
    expand(sys.argv[1], sys.argv[2], int(sys.argv[3]))
