FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN groupadd -g 1001 app  \
    && useradd -u 1001 -g app -d /opt/app -s /sbin/nologin app

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libgmp-dev \
    libssl-dev \
    libbenchmark-dev \
    python3 \
    python3-pip \
    python3-venv \
    python3-setuptools \
    python3-wheel \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir matplotlib numpy pandas

USER root

RUN git clone https://github.com/lallo-unitn/libgroupsig.git \
    && cd libgroupsig && mkdir build && cd build \
    && cmake -DUSE_GTEST=ON -DUSE_GCOV=OFF .. \
    && make && make test \
    && make install && ldconfig


RUN mkdir -p /usr/local/lib/pkgconfig && \
    printf '%s\n' \
'prefix=/usr/local' \
'exec_prefix=${prefix}' \
'libdir=${exec_prefix}/lib' \
'includedir=${prefix}/include/groupsig' \
'' \
'Name: libgroupsig' \
'Description: libgroupsig group signatures library' \
'Version: 1.0' \
'Libs: -L${libdir} -lgroupsig' \
'Cflags: -I${includedir}' \
> /usr/local/lib/pkgconfig/libgroupsig.pc && \
    echo "===== libgroupsig.pc inside build =====" && \
    cat /usr/local/lib/pkgconfig/libgroupsig.pc

ENV PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH}"
ENV GROUPSIG_ROOT="/usr/local"

WORKDIR /app
COPY . /app

RUN chown -R app:app /app

USER app

RUN rm -rf build

USER root

RUN chmod +x run_benchmarks.sh && \
    mkdir build && cd build && \
    cmake .. && \
    make

RUN chmod +x scripts/make_full_json.py && \
    chmod +x scripts/plotting_horizontal_grouped.py && \
    chmod +x scripts/plot_signature_lengths.py

USER root
CMD ["/bin/bash"]
