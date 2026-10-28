#!/usr/bin/env python3
# Copyright (c) 2026 Andrey Kuvshinov
# Dual-licensed under Apache-2.0 OR MIT.

"""Runs ./areion_pq_test --bench across all supported hardware tiers and prints a Markdown summary table."""

import os
import platform
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LINE_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*:\s*([0-9.]+)\s*MB/s\s*\(\s*([0-9.]+)\s*ns/op\)")
TIER_RE = re.compile(r"^Benchmarking active tier:\s*(\S+)")


def default_tiers() -> list[str]:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return ["purec", "aesni", "vex", "vaesavx2", "avx512"]
    if machine in ("aarch64", "arm64"):
        return ["purec", "arm64"]
    return ["purec"]


def main() -> int:
    tiers = sys.argv[1:] if len(sys.argv) > 1 else default_tiers()
    subprocess.run(["make", "-C", str(REPO_ROOT), "areion_pq_test"], check=True)
    test_bin = REPO_ROOT / "areion_pq_test"

    order: list[str] = []
    results: dict[str, dict[str, tuple[float, float]]] = {}
    active_tiers: list[str] = []

    for tier in tiers:
        env = dict(os.environ, AREION_PQ_FORCE_TIER=tier, AREION_FORCE_TIER=tier)
        proc = subprocess.run([str(test_bin), "--bench", tier], env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"# Skipping tier {tier} (exit={proc.returncode})", file=sys.stderr)
            continue
        out = proc.stdout
        detected = None
        for line in out.splitlines():
            m_tier = TIER_RE.match(line.strip())
            if m_tier:
                detected = m_tier.group(1)
                break
        if detected != tier:
            print(f"# Skipping tier {tier} (active={detected})", file=sys.stderr)
            continue

        active_tiers.append(tier)
        results[tier] = {}
        print(f"# Completed benchmark for tier: {tier}", file=sys.stderr)
        for line in out.splitlines():
            m = LINE_RE.match(line)
            if m:
                op, mb_s, ns_op = m.group(1), float(m.group(2)), float(m.group(3))
                if op not in order:
                    order.append(op)
                results[tier][op] = (mb_s, ns_op)

    if not active_tiers:
        print("No supported tiers were benchmarked.", file=sys.stderr)
        return 1

    header = "| Operation | " + " | ".join(f"`{t}` (MB/s / ns/op)" for t in active_tiers) + " |"
    sep = "|---|" + "|".join("---:" for _ in active_tiers) + "|"
    print(header)
    print(sep)
    for op in order:
        cells = []
        for t in active_tiers:
            if op in results[t]:
                mb_s, ns_op = results[t][op]
                cells.append(f"{mb_s:.1f} MB/s ({ns_op:.2f} ns)")
            else:
                cells.append("-")
        print(f"| `{op}` | " + " | ".join(cells) + " |")

    return 0


if __name__ == "__main__":
    sys.exit(main())
