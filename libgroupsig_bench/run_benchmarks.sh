#!/bin/bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

BUILD_DIR="./build"
BENCH_EXEC="${BUILD_DIR}/groupsig_bench"

PER_ITER_JSON_PATH="./scripts/per-iter.json"
FULL_JSON_PATH="./scripts/benchmark-results.json"

PLOT_SCRIPT="./scripts/plotting_horizontal_grouped.py"
SIGLEN_SCRIPT="./scripts/plot_signature_lengths.py"
AGG_SCRIPT="./scripts/make_full_json.py"

if [[ ! -x "${BENCH_EXEC}" ]]; then
  echo "Error: Benchmark executable not found or not executable at ${BENCH_EXEC}" >&2
  exit 1
fi

mkdir -p ./scripts

export PER_ITER_JSON="${PER_ITER_JSON_PATH}"

"${BENCH_EXEC}" \
  --benchmark_min_time=200 \
  --benchmark_repetitions=1 \
  --benchmark_display_aggregates_only=false \
  --benchmark_report_aggregates_only=false

if [[ ! -f "${PER_ITER_JSON_PATH}" ]]; then
  echo "Missing ${PER_ITER_JSON_PATH}" >&2
  exit 1
fi

python3 "${AGG_SCRIPT}" "${PER_ITER_JSON_PATH}" "${FULL_JSON_PATH}"

(
  cd scripts

  if [[ -f "$(basename "${PLOT_SCRIPT}")" ]]; then
    python3 "$(basename "${PLOT_SCRIPT}")" || true
  else
    echo "Warning: $(basename "${PLOT_SCRIPT}") not found, skipping horizontal plot." >&2
  fi

  if [[ -f "$(basename "${SIGLEN_SCRIPT}")" ]]; then
    python3 "$(basename "${SIGLEN_SCRIPT}")" || true
  else
    echo "Warning: $(basename "${SIGLEN_SCRIPT}") not found, skipping signature length plot." >&2
  fi
)

echo "Benchmark finished."
echo "  Per-iteration JSON                 : ${PER_ITER_JSON_PATH}"
echo "  Aggregated JSON                    : ${FULL_JSON_PATH}"
echo "  Horizontal grouped plot (PDF)      : ./scripts/benchmark_boxplots_horizontal.pdf"
echo "  Signature length plot (PDF)        : ./scripts/signature_lengths.pdf"