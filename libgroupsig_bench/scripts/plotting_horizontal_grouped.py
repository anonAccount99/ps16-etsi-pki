#!/usr/bin/env python3

import os
import json
from collections import defaultdict
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, LogFormatterMathtext, FormatStrFormatter, FuncFormatter


def load_json_safely(path):
    try:
        with open(path, 'r') as f:
            return json.load(f), None
    except Exception as e:
        return None, str(e)


def extract_benchmarks_from_data(data):
    if data is None:
        return []

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if 'benchmarks' in data and isinstance(data['benchmarks'], list):
            return data['benchmarks']

        per_iter_keys = [k for k in data.keys() if '.' in k and ('Sign' in k or 'Verify' in k)]
        if per_iter_keys:
            out = []
            for key, values in data.items():
                if isinstance(values, list) and len(values) > 0:
                    algorithm, operation = key.split('.', 1)
                    for i, value in enumerate(values):
                        out.append({
                            'name': f'BM_{algorithm}_{operation}/iteration:{i}',
                            'run_type': 'iteration',
                            'real_time': value,
                            'algorithm': algorithm,
                            'operation': operation
                        })
            return out

        for key, value in data.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value

        return []

    return []


def extract_algorithm_and_operation(benchmark_name):
    try:
        parts = benchmark_name.split('/')
        name_part = parts[0].replace('BM_', '')
        if '_Sign' in name_part:
            return name_part.replace('_Sign', ''), 'Sign'
        if '_Verify' in name_part:
            return name_part.replace('_Verify', ''), 'Verify'
        return name_part, 'Unknown'
    except Exception:
        return 'Unknown', 'Unknown'


def organize_data(aggregated_benchmarks, per_iter_benchmarks):
    organized = defaultdict(lambda: defaultdict(list))
    for bench in per_iter_benchmarks:
        if isinstance(bench, dict) and bench.get('run_type') == 'iteration':
            name = bench.get('name', '')
            if name:
                alg, op = extract_algorithm_and_operation(name)
                rt = bench.get('real_time', 0)
                if isinstance(rt, (int, float)):
                    organized[alg][op].append(float(rt) / 1000.0)
    return organized


def create_horizontal_two_panel_boxplots(organized):
    algorithms = sorted(organized.keys())
    ops = ['Sign', 'Verify']

    data_by_op = {}
    labels_by_op = {}
    for op in ops:
        labels = []
        data = []
        for alg in algorithms:
            series = organized[alg].get(op, [])
            if series:
                labels.append(alg)
                data.append(series)
        data_by_op[op] = data
        labels_by_op[op] = labels

    if not data_by_op['Sign'] and not data_by_op['Verify']:
        print('No data to plot')
        return None

    rows = 1
    cols = 2

    n_items = max(len(labels_by_op['Sign']), len(labels_by_op['Verify']), 1)
    height_per_item = 1.0
    base_height = 4.8
    panel_height = n_items * height_per_item + base_height
    fig_height = panel_height
    fig_width = 28.0
    figsize = (fig_width, fig_height)

    plt.rcParams.update({
        'axes.titlesize': 34,
        'axes.labelsize': 32,
        'xtick.labelsize': 28,
        'ytick.labelsize': 28,
        'legend.fontsize': 22
    })

    fig, axes = plt.subplots(rows, cols, figsize=figsize, sharex=False, sharey=False)
    axes = np.atleast_1d(axes)

    palette = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f']

    for i, op in enumerate(ops):
        ax = axes[i]
        data = data_by_op[op]
        labels = labels_by_op[op]
        if not data:
            ax.set_visible(False)
            continue

        bp = ax.boxplot(
            data,
            vert=False,
            patch_artist=True,
            labels=labels,
            showfliers=False,
            widths=0.9,
            medianprops={'linewidth': 2.8, 'color': 'black'}
        )

        for idx, patch in enumerate(bp['boxes']):
            patch.set_facecolor(palette[idx % len(palette)])
            patch.set_alpha(0.8)
            patch.set_linewidth(2.0)
        for whisker in bp['whiskers']:
            whisker.set_linewidth(2.0)
        for cap in bp['caps']:
            cap.set_linewidth(2.0)

        inliers_per_series = []
        for series in data:
            if len(series) == 0:
                inliers_per_series.append([])
                continue
            q1, q3 = np.percentile(series, [25, 75])
            iqr = q3 - q1
            lower = q1 - 1.5 * iqr
            upper = q3 + 1.5 * iqr
            inliers = [v for v in series if (v >= lower and v <= upper)]
            inliers_per_series.append(inliers)

        pooled = [v for s in inliers_per_series for v in s]
        if pooled:
            if op == 'Sign':
                min_inlier = min(pooled)
                p95 = np.percentile(pooled, 95)
                base_max = min(max(pooled), p95)
                x_min = min_inlier / 1.10
                x_max = base_max * 1.10
            else:
                base_min = min(pooled)
                base_max = max(pooled)
                drange = max(base_max - base_min, 1e-9)
                pad = max(drange * 0.15, 1e-9)
                x_min = base_min - pad
                x_max = base_max + pad
        else:
            base_min = min(min(series) for series in data)
            base_max = max(max(series) for series in data)
            if op == 'Sign':
                x_min = base_min / 1.10
                x_max = base_max * 1.10
            else:
                drange = max(base_max - base_min, 1e-9)
                pad = max(drange * 0.15, 1e-9)
                x_min = base_min - pad
                x_max = base_max + pad

        pos_candidates = pooled if pooled else [v for series in data for v in series if v > 0]
        if pos_candidates:
            smallest_pos = float(np.min([v for v in pos_candidates if v > 0]))
            if x_min <= 0:
                x_min = max(smallest_pos * 0.7, 1e-12)
            if x_max <= 0:
                x_max = smallest_pos * 1.3
            if x_max <= x_min * 1.01:
                x_max = x_min * 1.2
            ax.set_xscale('log', base=10)
            if op == 'Sign':
                def custom_major_formatter(x, pos):
                    if x == 1:
                        return "1"
                    return LogFormatterMathtext(base=10.0)(x, pos)
                major_formatter = FuncFormatter(custom_major_formatter)
                minor_subs = np.arange(2.0, 10.0)
            else:
                major_formatter = LogFormatterMathtext(base=10.0)
                minor_subs = (2, 5)
            minor_formatter = FormatStrFormatter("%.2g")
            ax.xaxis.set_major_locator(LogLocator(base=10.0, numticks=15))
            ax.xaxis.set_minor_locator(LogLocator(base=10.0, subs=minor_subs, numticks=15))
            ax.xaxis.set_major_formatter(major_formatter)
            ax.xaxis.set_minor_formatter(minor_formatter)
            ax.tick_params(axis='x', which='major', labelsize=28, rotation=0)
            ax.tick_params(axis='x', which='minor', labelsize=28, rotation=45)
        else:
            if x_min < 0:
                x_min = 0
            if x_max <= x_min * 1.01:
                x_max = x_min + 1.0

        ax.set_xlim(x_min, x_max)
        ax.tick_params(axis='y', which='both', labelsize=28)

        for j, inliers in enumerate(inliers_per_series, start=1):
            if not inliers:
                continue
            y = np.random.normal(j, 0.06, size=len(inliers))
            ax.scatter(inliers, y, alpha=0.35, s=18, color='black', zorder=3)

        for j, series in enumerate(data, start=1):
            if not series:
                continue
            mean_val = float(np.mean(series))
            std_val = float(np.std(series))
            label_text = f"μ={mean_val:.3f}\nσ={std_val:.3f}"
            label_name = labels[j-1]
            if op == 'Verify':
                if label_name == 'GL19':
                    ax.annotate(
                        label_text,
                        xy=(mean_val, j),
                        xytext=(-70, 0),
                        textcoords='offset points',
                        va='center',
                        ha='right',
                        fontsize=26,
                        color='black',
                        zorder=4,
                        bbox=dict(boxstyle='round,pad=0.34', facecolor='white', alpha=0.87, linewidth=0.8),
                    )
                else:
                    base_east = 120
                    extra_shift = 24 if label_name == 'DL21_SEQ' else 0
                    ax.annotate(
                        label_text,
                        xy=(mean_val, j),
                        xytext=(base_east + extra_shift, 0),
                        textcoords='offset points',
                        va='center',
                        ha='left',
                        fontsize=26,
                        color='black',
                        zorder=4,
                        bbox=dict(boxstyle='round,pad=0.34', facecolor='white', alpha=0.87, linewidth=0.8),
                    )
            else:
                if mean_val < 1.0:
                    ax.annotate(
                        label_text,
                        xy=(mean_val, j),
                        xytext=(36, 0),
                        textcoords='offset points',
                        va='center',
                        ha='left',
                        fontsize=26,
                        color='black',
                        zorder=4,
                        bbox=dict(boxstyle='round,pad=0.34', facecolor='white', alpha=0.87, linewidth=0.8),
                    )
                else:
                    ax.annotate(
                        label_text,
                        xy=(mean_val, j),
                        xytext=(-40, 0),
                        textcoords='offset points',
                        va='center',
                        ha='right',
                        fontsize=26,
                        color='black',
                        zorder=4,
                        bbox=dict(boxstyle='round,pad=0.34', facecolor='white', alpha=0.87, linewidth=0.8),
                    )

        ax.grid(True, which='both', alpha=0.4, linestyle='--')
        ax.set_xlabel('Time (ms)')
        ax.set_title(op)

        if op == 'Verify':
            ax.set_ylabel('')
            ax.set_yticklabels([])
            ax.tick_params(axis='y', labelleft=False)

    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.subplots_adjust(wspace=0.08)
    return fig


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    agg_path = os.path.join(base_dir, 'benchmark-results.json')
    per_iter_path = os.path.join(base_dir, 'per-iter.json')

    agg_data, agg_err = load_json_safely(agg_path)
    per_iter_data, per_err = load_json_safely(per_iter_path)

    if agg_err:
        print(f'Error loading aggregated data: {agg_err}')
        return
    if per_err:
        print(f'Error loading per-iteration data: {per_err}')
        return

    aggregated_benchmarks = extract_benchmarks_from_data(agg_data)
    per_iter_benchmarks = extract_benchmarks_from_data(per_iter_data)

    if not aggregated_benchmarks or not per_iter_benchmarks:
        print('Missing benchmarks data to plot')
        return

    organized = organize_data(aggregated_benchmarks, per_iter_benchmarks)

    fig = create_horizontal_two_panel_boxplots(organized)
    if fig is None:
        return

    out_path = os.path.join(base_dir, 'benchmark_boxplots_horizontal.pdf')
    fig.savefig(out_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f'Saved: {out_path}')


if __name__ == '__main__':
    main()
