#!/usr/bin/env python3
import json
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
from matplotlib.ticker import LogLocator

def load_benchmark_data(filename):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        print(f"Successfully loaded {len(data)} entries from {filename}")
        return data
    except FileNotFoundError:
        print(f"Error: The file {filename} was not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {filename}.")
        return []

def extract_benchmark_metrics(data):
    results = defaultdict(lambda: defaultdict(list))
    for entry in data:
        try:
            parts = entry['benchmark'].split('.')
            tech = 'etsi103097' if 'etsi103097' in parts else 'groupsig'
            op = 'Sign' if 'Generator' in parts[-2] else 'Verify'
            key = (tech, op)
            mode = entry['mode']
            if mode == 'avgt':
                score = entry['primaryMetric']['score']
                raw_data = entry['primaryMetric'].get('rawData', [[]])
                if raw_data and raw_data[0]:
                    flat_data = [item for sublist in raw_data for item in sublist]
                    results[key][mode].extend(flat_data)
                else:
                    results[key][mode].append(score)
        except (KeyError, IndexError) as e:
            print(f"Skipping malformed entry: {entry}. Error: {e}")
    return results

def lens_transform(y, centers=(0.461, 1.7), widths=(0.04, 0.06), strengths=(0.28, 0.30)):
    y_arr = np.asarray(y, dtype=float)
    z = y_arr.copy()
    for c, w, s in zip(centers, widths, strengths):
        z = z + s * np.arctan((y_arr - c) / w)
    return z

def format_tick_label(v, focus_points=None):
    if focus_points is None:
        focus_points = []
    for f in focus_points:
        if abs(v - f) < 1e-6:
            return f"{v:.3f}"
    if v < 10:
        return f"{v:.2f}"
    if v < 100:
        return f"{v:.1f}"
    return f"{v:.0f}"

def create_comparison_chart(results):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 7))

    sign_data_ms = [
        [x/1000 for x in results[('etsi103097', 'Sign')]['avgt']],
        [x/1000 for x in results[('groupsig', 'Sign')]['avgt']]
    ]
    verify_data_ms = [
        [x/1000 for x in results[('etsi103097', 'Verify')]['avgt']],
        [x/1000 for x in results[('groupsig', 'Verify')]['avgt']]
    ]

    plot_labels = ['ETSI TS 103 097', 'PS16 (Java)']
    x_pos = np.arange(len(plot_labels))

    transformed_sign = [lens_transform(np.array(d), centers=(0.461, 1.710), widths=(0.04, 0.06), strengths=(0.28, 0.30)) for d in sign_data_ms]
    bp1 = ax1.boxplot(transformed_sign, positions=x_pos, vert=True, patch_artist=True, widths=0.45)
    ax1.set_title('Signing Time', fontsize=24)
    ax1.set_ylabel('Time (ms/op)', fontsize=20)

    y_lower, y_upper = 0.30, 2.20
    lower_t = lens_transform(np.array([y_lower]), centers=(0.461, 1.710), widths=(0.04, 0.06), strengths=(0.28, 0.30))[0]
    upper_t = lens_transform(np.array([y_upper]), centers=(0.461, 1.710), widths=(0.04, 0.06), strengths=(0.28, 0.30))[0]
    ax1.set_ylim(lower_t, upper_t)

    tick_candidates_sign = [0.30, 0.40, 0.461, 0.50, 0.60, 0.70, 0.90, 1.10, 1.30, 1.50, 1.60, 1.65, 1.710, 1.75, 1.80, 2.10]
    ax1.set_yticks(lens_transform(tick_candidates_sign, centers=(0.461, 1.710), widths=(0.04, 0.06), strengths=(0.28, 0.30)))
    ax1.set_yticklabels([format_tick_label(v, focus_points=[0.461, 1.710]) for v in tick_candidates_sign])

    ax1.grid(True, which='major', linestyle='-', linewidth=0.8, color='gray', alpha=0.3)
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(plot_labels)
    ax1.tick_params(axis='x', labelsize=18)
    ax1.tick_params(axis='y', labelsize=16)

    colors = ['#3498db', '#800080']
    for patch, color in zip(bp1['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    for i, line in enumerate(bp1['medians']):
        y_med = line.get_ydata()[0]
        mean_val = np.mean(sign_data_ms[i])
        std_val = np.std(sign_data_ms[i])
        if i == 0:
            x = line.get_xdata()[1] + 0.06
            ax1.text(x, y_med, f'μ={mean_val:.3f}\nσ={std_val:.3f}', va='center', ha='left', fontsize=12, color='black', fontweight='bold', bbox=dict(boxstyle='round,pad=0.25', fc='white', ec='gray', alpha=0.8))
        else:
            x = line.get_xdata()[0] - 0.06
            ax1.text(x, y_med, f'μ={mean_val:.3f}\nσ={std_val:.3f}', va='center', ha='right', fontsize=12, color='black', fontweight='bold', bbox=dict(boxstyle='round,pad=0.25', fc='white', ec='gray', alpha=0.8))

    centers_v = (0.368, 3.444)
    widths_v = (0.03, 0.12)
    strengths_v = (0.28, 0.30)
    transformed_verify = [lens_transform(np.array(d), centers=centers_v, widths=widths_v, strengths=strengths_v) for d in verify_data_ms]
    bp2 = ax2.boxplot(transformed_verify, positions=x_pos, vert=True, patch_artist=True, widths=0.45)
    ax2.set_title('Verification Time', fontsize=24)
    ax2.set_ylabel('Time (ms/op)', fontsize=20)

    all_verify = np.concatenate([np.asarray(d, dtype=float) for d in verify_data_ms]) if all(len(d) for d in verify_data_ms) else np.array([0.1, 10.0])
    y_min_v = float(np.min(all_verify))
    y_max_v = float(np.max(all_verify))
    span_v = y_max_v - y_min_v if y_max_v > y_min_v else 1.0
    y_lower_v = max(0.0, y_min_v - 0.1 * span_v)
    y_upper_v = y_max_v + 0.1 * span_v
    ax2.set_ylim(lens_transform([y_lower_v], centers=centers_v, widths=widths_v, strengths=strengths_v)[0],
                 lens_transform([y_upper_v], centers=centers_v, widths=widths_v, strengths=strengths_v)[0])

    tick_candidates_verify = [0.10, 0.30, 0.368, 0.40, 0.60, 0.80, 1.0, 1.20, 1.40, 2.00, 2.50, 3.00, 3.20, 3.30, 3.40, 3.444, 3.50, 3.60, 4.00, 5.00]
    ax2.set_yticks(lens_transform(tick_candidates_verify, centers=centers_v, widths=widths_v, strengths=strengths_v))
    ax2.set_yticklabels([format_tick_label(v, focus_points=list(centers_v)) for v in tick_candidates_verify])

    ax2.grid(True, which='major', linestyle='-', linewidth=0.8, color='gray', alpha=0.3)
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(plot_labels)
    ax2.tick_params(axis='x', labelsize=18)
    ax2.tick_params(axis='y', labelsize=16)

    for patch, color in zip(bp2['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    for i, line in enumerate(bp2['medians']):
        y = line.get_ydata()[0]
        mean_val = np.mean(verify_data_ms[i])
        std_val = np.std(verify_data_ms[i])
        if i == 0:
            x = line.get_xdata()[1] + 0.06
            ax2.text(x, y, f'μ={mean_val:.3f}\nσ={std_val:.3f}', va='center', ha='left', fontsize=12, color='black', fontweight='bold', bbox=dict(boxstyle='round,pad=0.25', fc='white', ec='gray', alpha=0.8))
        else:
            x = line.get_xdata()[0] - 0.06
            ax2.text(x, y, f'μ={mean_val:.3f}\nσ={std_val:.3f}', va='center', ha='right', fontsize=12, color='black', fontweight='bold', bbox=dict(boxstyle='round,pad=0.25', fc='white', ec='gray', alpha=0.8))

    # This are hardcoded, you can check this values by de-commenting code in its-station/Main.java so that it will return these lengths
    etsi_msg = 40
    etsi_cert_sig = 244
    ps16_msg = 40
    ps16_sig = 242

    ax3.set_title('DENM Length', fontsize=24)
    ax3.set_ylabel('Bytes', fontsize=20)
    schemes = ['ETSI', 'PS16']
    xpos = np.arange(2)
    msg_heights = [etsi_msg, ps16_msg]
    sig_heights = [etsi_cert_sig, ps16_sig]
    ax3.bar(xpos, msg_heights, width=0.5, label='Message', alpha=0.8)
    ax3.bar(xpos, sig_heights, width=0.5, bottom=msg_heights, label='Certificate/Signature', alpha=0.8)
    totals = [m + s for m, s in zip(msg_heights, sig_heights)]
    for x, t in zip(xpos, totals):
        ax3.text(x, t + 6, f'{t}', ha='center', va='bottom', fontsize=12, fontweight='bold')
    ax3.set_xticks(xpos)
    ax3.set_xticklabels(schemes, fontsize=18)
    ax3.tick_params(axis='y', labelsize=16)
    ax3.set_ylim(0, 400)
    ax3.grid(True, axis='y', linestyle='-', linewidth=0.8, color='gray', alpha=0.3)
    ax3.legend(fontsize=12, loc='upper right')

    fig.tight_layout(pad=0.8, w_pad=0.6, h_pad=0.6)
    output_filename = 'sign_verify_comparison.pdf'
    plt.savefig(output_filename, format='pdf', bbox_inches='tight')
    print(f"Chart saved to {output_filename}")

def main():
    data = load_benchmark_data('benchmark-results.json')
    if not data:
        return
    results = extract_benchmark_metrics(data)
    if not results:
        print("No valid benchmark data found to create a chart.")
        return
    create_comparison_chart(results)

if __name__ == "__main__":
    main()
