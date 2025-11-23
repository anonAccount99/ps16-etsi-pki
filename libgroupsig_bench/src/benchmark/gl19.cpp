#include <benchmark/benchmark.h>
#include <chrono>
#include <string>
extern "C" {
#include "../include/gl19_bench.h"
}
void per_iter_append(const char*, long long);

static void BM_GL19_Sign(benchmark::State& st)
{
    auto* ctx = gl19_bench_setup();
    for (auto _ : st) {
        auto t0 = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(ctx);
        gl19_bench_sign(ctx);
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> sec = t1 - t0;
        st.SetIterationTime(sec.count());
        per_iter_append("GL19.Sign", std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }
    gl19_bench_teardown(ctx);
}
BENCHMARK(BM_GL19_Sign)->UseManualTime()->Iterations(250)->ReportAggregatesOnly(false)->Unit(benchmark::kMicrosecond);

static void BM_GL19_Verify(benchmark::State& st)
{
    auto* ctx = gl19_bench_setup();
    gl19_bench_sign(ctx);
    for (auto _ : st) {
        auto t0 = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(gl19_bench_verify(ctx));
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> sec = t1 - t0;
        st.SetIterationTime(sec.count());
        per_iter_append("GL19.Verify", std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }
    gl19_bench_teardown(ctx);
}
BENCHMARK(BM_GL19_Verify)->UseManualTime()->Iterations(250)->ReportAggregatesOnly(false)->Unit(benchmark::kMicrosecond);
