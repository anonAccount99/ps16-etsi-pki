#include <benchmark/benchmark.h>
#include <chrono>
#include <string>
extern "C" {
#include "../include/ps16_bench.h"
}
void per_iter_append(const char*, long long);

static void BM_PS16_Sign(benchmark::State& st)
{
    auto* ctx = ps16_bench_setup();
    for (auto _ : st) {
        auto t0 = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(ctx);
        ps16_bench_sign(ctx);
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> sec = t1 - t0;
        st.SetIterationTime(sec.count());
        per_iter_append("PS16.Sign", std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }
    ps16_bench_teardown(ctx);
}
BENCHMARK(BM_PS16_Sign)->UseManualTime()->Iterations(250)->ReportAggregatesOnly(false)->Unit(benchmark::kMicrosecond);

static void BM_PS16_Verify(benchmark::State& st)
{
    auto* ctx = ps16_bench_setup();
    ps16_bench_sign(ctx);
    for (auto _ : st) {
        auto t0 = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(ps16_bench_verify(ctx));
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> sec = t1 - t0;
        st.SetIterationTime(sec.count());
        per_iter_append("PS16.Verify", std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }
    ps16_bench_teardown(ctx);
}
BENCHMARK(BM_PS16_Verify)->UseManualTime()->Iterations(250)->ReportAggregatesOnly(false)->Unit(benchmark::kMicrosecond);
