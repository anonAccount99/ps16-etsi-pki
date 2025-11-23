#include <benchmark/benchmark.h>
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <cstdlib>
using namespace std;

static map<string, vector<long long>>& per_iter_map() {
    static map<string, vector<long long>> m;
    return m;
}

extern "C++" void per_iter_append(const char* name, long long micros) {
    per_iter_map()[string(name)].push_back(micros);
}

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);
    int rc = ::benchmark::RunSpecifiedBenchmarks();

    const char* path = std::getenv("PER_ITER_JSON");
    const string file = path ? string(path) : string("per-iter.json");
    ofstream os(file);
    os << "{\n";
    bool first_bench = true;
    for (const auto& kv : per_iter_map()) {
        if (!first_bench) os << ",\n";
        first_bench = false;
        os << "  \"" << kv.first << "\": [";
        for (size_t i = 0; i < kv.second.size(); ++i) {
            if (i) os << ",";
            os << kv.second[i];
        }
        os << "]";
    }
    os << "\n}\n";
    os.close();

    return rc;
}
