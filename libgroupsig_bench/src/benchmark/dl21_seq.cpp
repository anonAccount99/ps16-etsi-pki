#include <benchmark/benchmark.h>
#include <chrono>
#include <string>
extern "C" {
#include "../include/dl21_seq_bench.h"
}
void per_iter_append(const char*, long long);

static void BM_DL21_SEQ_Sign(benchmark::State& st)
{
    auto* ctx = dl21_seq_bench_setup();
    for (auto _ : st) {
        auto t0 = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(ctx);
        dl21_seq_bench_sign(ctx);
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> sec = t1 - t0;
        st.SetIterationTime(sec.count());
        per_iter_append("DL21_SEQ.Sign", std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }
    dl21_seq_bench_teardown(ctx);
}
BENCHMARK(BM_DL21_SEQ_Sign)->UseManualTime()->Iterations(250)->ReportAggregatesOnly(false)->Unit(benchmark::kMicrosecond);

static void BM_DL21_SEQ_Verify(benchmark::State& st)
{
    auto* ctx = dl21_seq_bench_setup();
    dl21_seq_bench_sign(ctx);
    for (auto _ : st) {
        auto t0 = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(dl21_seq_bench_verify(ctx));
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> sec = t1 - t0;
        st.SetIterationTime(sec.count());
        per_iter_append("DL21_SEQ.Verify", std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }
    dl21_seq_bench_teardown(ctx);
}
BENCHMARK(BM_DL21_SEQ_Verify)->UseManualTime()->Iterations(250)->ReportAggregatesOnly(false)->Unit(benchmark::kMicrosecond);
