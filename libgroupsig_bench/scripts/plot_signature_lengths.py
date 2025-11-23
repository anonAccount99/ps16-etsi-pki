#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import sys
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
import numpy as np

BASE_COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']

EXPECTED_SCHEMES = [
    'BBS04',
    'DL21_SEQ',
    'GL19',
    'KLAP20',
    'PS16',
]

ROW_RE = re.compile(r"^\|\s*([A-Z0-9_]+)\s*\|\s*(\d+)\s+bytes\s*\|\s*$")


def find_project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def run_measure_binary(binary_path: str) -> Tuple[Dict[str, int], str]:
    cwd = find_project_root()
    try:
        proc = subprocess.run(
            [binary_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
        )
    except FileNotFoundError:
        raise FileNotFoundError(f"Binary not found: {binary_path}. Build it first (e.g., via CMake).")
    except subprocess.CalledProcessError as e:
        combined = ''
        if e.stdout:
            combined += e.stdout
        if e.stderr:
            if combined:
                combined += "\n"
            combined += e.stderr
        raise RuntimeError(f"Failed running {binary_path} (cwd={cwd}): {combined.strip()}")

    output = proc.stdout
    sizes: Dict[str, int] = {}
    for line in output.splitlines():
        m = ROW_RE.match(line.strip())
        if m:
            scheme, size_str = m.group(1), m.group(2)
            try:
                sizes[scheme] = int(size_str)
            except ValueError:
                pass
    if not sizes:
        raise ValueError("Could not parse any signature sizes from program output.")
    return sizes, output


def parse_from_file(path: str) -> Dict[str, int]:
    with open(path, 'r', encoding='utf-8') as f:
        sizes: Dict[str, int] = {}
        for line in f:
            m = ROW_RE.match(line.strip())
            if m:
                scheme, size_str = m.group(1), m.group(2)
                sizes[scheme] = int(size_str)
    if not sizes:
        raise ValueError(f"No sizes found in file: {path}")
    return sizes


def build_color_map(schemes_sorted: List[str]) -> Dict[str, str]:
    color_map: Dict[str, str] = {}
    for idx, scheme in enumerate(schemes_sorted):
        color_map[scheme] = BASE_COLORS[idx % len(BASE_COLORS)]
    return color_map


def plot_signature_lengths(sizes: Dict[str, int], output: str, show: bool) -> None:
    schemes = sorted(sizes.keys())

    color_map = build_color_map(schemes)

    values = [sizes[s] for s in schemes]
    colors = [color_map[s] for s in schemes]

    plt.style.use('default')
    fig, ax = plt.subplots(figsize=(10, 6))

    spacing = 0.7
    x = np.arange(len(schemes)) * spacing

    bars = ax.bar(x, values, color=colors, edgecolor='black', linewidth=1.2, width=0.45)

    ax.set_ylabel('Signature size (bytes)')
    ax.set_title('Signature Lengths by Scheme')
    ax.grid(axis='y', linestyle='--', alpha=0.3)

    ax.set_xticks(x)
    ax.set_xticklabels(schemes)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.01,
                f"{val}", ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    out_path = output or os.path.join(os.path.dirname(__file__), 'signature_lengths.pdf')
    fig.savefig(out_path, dpi=300, bbox_inches='tight')
    print(f"Saved signature length chart to: {out_path}")

    if show:
        try:
            plt.show()
        except Exception:
            pass


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description='Plot signature lengths by scheme with consistent colors.')
    parser.add_argument('--from-file', dest='from_file', help='Parse sizes from a text file containing the table output.')
    parser.add_argument('--binary', dest='binary', help='Path to the measure_signatures binary. Defaults to ../build/measure_signatures')
    parser.add_argument('--output', dest='output', help='Output image path (png/pdf). Defaults to scripts/signature_lengths.pdf')
    parser.add_argument('--show', action='store_true', help='Show the plot window after saving.')

    args = parser.parse_args(argv)

    sizes: Dict[str, int]

    if args.from_file:
        sizes = parse_from_file(args.from_file)
    else:
        root = find_project_root()
        binary = args.binary or os.path.join(root, 'build', 'measure_signatures')
        sizes, raw_output = run_measure_binary(binary)
        try:
            out_txt = os.path.join(os.path.dirname(__file__), 'signature_lengths.txt')
            with open(out_txt, 'w', encoding='utf-8') as f:
                f.write(raw_output)
        except Exception:
            pass

    plot_signature_lengths(sizes, args.output, args.show)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
