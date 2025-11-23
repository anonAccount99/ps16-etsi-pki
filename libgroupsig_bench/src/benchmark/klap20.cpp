#include <benchmark/benchmark.h>
#include <chrono>
#include <string>
extern "C" {
#include "../include/klap20_bench.h"
}
void per_iter_append(const char*, long long);

static void BM_KLAP20_Sign(benchmark::State& st)
{
    auto* ctx = klap20_bench_setup();
    for (auto _ : st) {
        auto t0 = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(ctx);
        klap20_bench_sign(ctx);
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> sec = t1 - t0;
        st.SetIterationTime(sec.count());
        per_iter_append("KLAP20.Sign", std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }
    klap20_bench_teardown(ctx);
}
BENCHMARK(BM_KLAP20_Sign)->UseManualTime()->Iterations(250)->ReportAggregatesOnly(false)->Unit(benchmark::kMicrosecond);

static void BM_KLAP20_Verify(benchmark::State& st)
{
    auto* ctx = klap20_bench_setup();
    klap20_bench_sign(ctx);
    for (auto _ : st) {
        auto t0 = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(klap20_bench_verify(ctx));
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> sec = t1 - t0;
        st.SetIterationTime(sec.count());
        per_iter_append("KLAP20.Verify", std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }
    klap20_bench_teardown(ctx);
}
BENCHMARK(BM_KLAP20_Verify)->UseManualTime()->Iterations(250)->ReportAggregatesOnly(false)->Unit(benchmark::kMicrosecond);