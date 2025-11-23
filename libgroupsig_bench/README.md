# libgroupsig-bench
Micro-benchmarks for three group-signature schemes shipped with this fork of **[libgroupsig](https://github.com/lallo-unitn/libgroupsig)**.

| scheme | original paper | benchmark helper |
|--------|----------------|------------------|
| **BBS04** | Boneh–Boyen–Shacham (2004) | `src/benchmark/bbs04_bench.cpp` |
| **PS16** | Pointcheval–Sanders (2016)  | `src/benchmark/ps16_bench.cpp` |
| **GL19** | García-López *et al.* (2019) | `src/benchmark/gl19_bench.cpp` |
| **KLAP20** | Kim *et al.* (2020) | `src/benchmark/klap20_bench.cpp` |
| **DL21Seq** | Diaz-Lehmann (2021) | `src/benchmark/dl21_seq_bench.cpp` |

Google Benchmark measures **sign**, **verify**, and **sign + verify** for each
scheme; a short Python script converts the JSON output into an error-bar chart.

## Requirements

| package | tested version |
|---------|----------------|
| **libgroupsig** (+ `mcl`, `gmp`, etc.) | current *main* |
| **Google Benchmark** | ≥ 1.8 |
| **CMake** | ≥ 3.15 |
| **C compiler** | C11 |
| **C++ compiler** | C++17 |
| **Python 3** with `matplotlib` and `pandas` | ≥ 3.8 |
