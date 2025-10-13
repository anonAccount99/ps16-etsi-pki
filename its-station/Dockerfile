FROM registry.access.redhat.com/ubi9-minimal:9.6-1752069876 AS builder

RUN microdnf install -y --nodocs java-21-openjdk-devel gcc gcc-c++ make cmake  \
    git maven tar unzip openssl-devel gmp-devel glib2-devel  \
    && microdnf clean all

RUN groupadd -g 1001 app  \
    && useradd -u 1001 -g app -d /opt/app -s /sbin/nologin app

RUN mkdir -p /workspace /opt/app/.m2 /opt/app/.gradle  \
    && chown -R app:app /workspace /opt/app

USER app

WORKDIR /workspace

USER root

RUN git clone https://github.com/lallo-unitn/libgroupsig.git \
    && cd libgroupsig && mkdir build && cd build \
    && cmake -DUSE_GTEST=ON -DUSE_GCOV=OFF .. \
    && make && make test \
    && make install

RUN chown -R app:0 /workspace

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH=${JAVA_HOME}/bin:${PATH}

RUN cd libgroupsig/src/wrappers/java/jgroupsig && mvn -q clean install

COPY --chown=app:app . .

RUN chmod +x gradlew

RUN ./gradlew :its-station:shadowJar --no-daemon --stacktrace

FROM registry.access.redhat.com/ubi9-minimal:9.6-1752069876
RUN microdnf install -y --nodocs java-21-openjdk  \
    && microdnf clean all

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH=${JAVA_HOME}/bin:${PATH}

COPY --from=builder /usr/local/lib/libgroupsig.so /usr/lib64/
COPY --from=builder /usr/local/lib/libmcl*.so* /usr/lib64/
COPY --from=builder /workspace/libgroupsig/src/wrappers/java/jgroupsig/java/target/main/resources/libjnigroupsig.so /usr/lib64/
COPY --from=builder /workspace/its-station/build/libs/its-station.jar /app/its-station.jar
RUN ldconfig

RUN mkdir -p /app/results && chmod 1777 /app/results

USER 1001
WORKDIR /app

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PATH=${JAVA_HOME}/bin:${PATH}

ENTRYPOINT ["java","-jar","its-station.jar"]