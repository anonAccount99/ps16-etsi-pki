cmake_minimum_required(VERSION 3.15)

project(groupsig LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

if(GROUPSIG_ROOT)
    list(APPEND ENV{PKG_CONFIG_PATH}
            "$ENV{PKG_CONFIG_PATH}:${GROUPSIG_ROOT}/lib/pkgconfig")
endif()
pkg_check_modules(GROUPSIG REQUIRED IMPORTED_TARGET libgroupsig)

option(ENABLE_BENCHMARK "Build micro-benchmarks with Google Benchmark" ON)

if(ENABLE_BENCHMARK)
    find_package(benchmark QUIET CONFIG)
    if(NOT benchmark_FOUND)
        message(WARNING "Google Benchmark not found – benchmarks will be skipped.")
        set(ENABLE_BENCHMARK OFF)
    endif()
endif()

add_executable(measure_signatures
        src/measure_signatures.c
        src/snippets/gl19_bench.c
        src/snippets/ps16_bench.c
        src/snippets/bbs04_bench.c
        src/snippets/klap20_bench.c
        src/snippets/dl21_seq_bench.c
        src/snippets/input_message.c)

target_include_directories(measure_signatures PRIVATE ${GROUPSIG_INCLUDE_DIRS})
target_compile_options  (measure_signatures PRIVATE ${GROUPSIG_CFLAGS_OTHER})
target_link_options     (measure_signatures PRIVATE ${GROUPSIG_LDFLAGS_OTHER})
target_link_libraries   (measure_signatures PRIVATE ${GROUPSIG_LIBRARIES})

if(ENABLE_BENCHMARK)
    add_executable(groupsig_bench
            src/benchmark/gl19.cpp
            src/benchmark/ps16.cpp
            src/benchmark/bbs04.cpp
            src/benchmark/klap20.cpp
            src/benchmark/dl21_seq.cpp
            src/benchmark/driver.cpp
            src/snippets/gl19_bench.c
            src/snippets/ps16_bench.c
            src/snippets/bbs04_bench.c
            src/snippets/klap20_bench.c
            src/snippets/dl21_seq_bench.c
            src/snippets/input_message.c
            src/include/input_message.h
            src/benchmark/klap20.cpp
    )

    target_include_directories(groupsig_bench PRIVATE ${GROUPSIG_INCLUDE_DIRS})
    target_compile_options  (groupsig_bench PRIVATE ${GROUPSIG_CFLAGS_OTHER})
    target_link_options     (groupsig_bench PRIVATE ${GROUPSIG_LDFLAGS_OTHER})

    target_link_libraries(groupsig_bench PRIVATE
            ${GROUPSIG_LIBRARIES}
            benchmark::benchmark
            benchmark::benchmark_main
            pthread)
endif()


find_package(Python3 REQUIRED COMPONENTS Interpreter)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

if(ENABLE_BENCHMARK)
    set(BENCH_JSON  ${CMAKE_BINARY_DIR}/benchmark_results.json)
    set(BENCH_PNG   ${CMAKE_SOURCE_DIR}/benchmark_results.png)

    if(EXISTS "${CMAKE_SOURCE_DIR}/scripts/plotting_horizontal_grouped.py")
        set(PLOT_SCRIPT "${CMAKE_SOURCE_DIR}/scripts/plotting_horizontal_grouped.py")
    elseif(EXISTS "${CMAKE_SOURCE_DIR}/scripts/plotting.py")
        set(PLOT_SCRIPT "${CMAKE_SOURCE_DIR}/scripts/plotting.py")
    else()
        message(WARNING
                "No plotting script found in ${CMAKE_SOURCE_DIR}/scripts; "
                "bench_with_plot target will be disabled.")
        set(PLOT_SCRIPT "")
    endif()

    if(PLOT_SCRIPT)
        add_custom_command(
                OUTPUT  ${BENCH_JSON}
                COMMAND $<TARGET_FILE:groupsig_bench>
                --benchmark_min_time=200
                --benchmark_repetitions=250
                --benchmark_report_aggregates_only=true
                --benchmark_out=${BENCH_JSON}
                --benchmark_out_format=json
                DEPENDS groupsig_bench
                COMMENT "Running Google Benchmark → ${BENCH_JSON}"
                VERBATIM)

        add_custom_command(
                OUTPUT  ${BENCH_PNG}
                COMMAND ${Python3_EXECUTABLE} ${PLOT_SCRIPT} ${BENCH_JSON} ${BENCH_PNG}
                DEPENDS ${BENCH_JSON}
                COMMENT "Generating chart → ${BENCH_PNG}"
                VERBATIM)

        add_custom_target(bench_with_plot
                DEPENDS ${BENCH_PNG})
    endif()
endif()


message(STATUS "Groupsig include dirs : ${GROUPSIG_INCLUDE_DIRS}")
message(STATUS "Groupsig libraries    : ${GROUPSIG_LIBRARIES}")
message(STATUS "Google Benchmark      : ${ENABLE_BENCHMARK}")
message(STATUS "Python3 interpreter   : ${Python3_EXECUTABLE}")