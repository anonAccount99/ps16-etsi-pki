FROM quay.io/wildfly/wildfly:36.0.0.Final-jdk21

USER root
RUN microdnf install -y --nodocs \
        gcc gcc-c++ make cmake git maven tar unzip\
        openssl-devel gmp-devel glib2-devel \
    && microdnf install -y --nodocs openssl-libs gmp glib2 \
    && microdnf clean all

RUN mkdir -p /workspace \
    && mkdir -p /opt/jboss/.m2/repository \
    && mkdir -p /opt/jboss/.gradle \
    && chown -R jboss:0 /workspace /opt/jboss/.m2 /opt/jboss/.gradle

WORKDIR /workspace

USER root

RUN git clone https://github.com/lallo-unitn/libgroupsig.git \
    && cd libgroupsig && mkdir build && cd build \
    && cmake -DUSE_GTEST=ON -DUSE_GCOV=ON .. \
    && make && make test \
    && make install

RUN chown -R jboss:0 /workspace

USER jboss

RUN cd /workspace/libgroupsig/src/wrappers/java/jgroupsig \
 && mvn clean install

COPY gradlew gradlew
COPY gradlew.bat gradlew.bat
COPY gradle/wrapper/gradle-wrapper.jar gradle/wrapper/gradle-wrapper.jar
COPY gradle/wrapper/gradle-wrapper.properties gradle/wrapper/gradle-wrapper.properties

COPY build.gradle build.gradle
COPY settings.gradle settings.gradle
COPY settings*.gradle ./
COPY root-ca/build.gradle root-ca/

USER root

RUN chown -R jboss:0 /workspace

USER jboss

RUN ./gradlew :root-ca:downloadDependencies

COPY . .

USER root

RUN cp /workspace/libgroupsig/src/wrappers/java/jgroupsig/java/target/main/resources/libjnigroupsig.so $JBOSS_HOME/standalone/deployments/

RUN cp /usr/local/lib/libgroupsig.so /usr/lib64/ && \
    cp /workspace/libgroupsig/src/wrappers/java/jgroupsig/java/target/main/resources/libjnigroupsig.so /usr/lib64/

RUN chown -R jboss:0 $JBOSS_HOME/standalone/deployments
RUN chown -R jboss:0 /workspace

USER jboss

RUN ./gradlew :root-ca:war

RUN cp /workspace/root-ca/build/libs/root-ca-*.war $JBOSS_HOME/standalone/deployments/root.war

ENV ADMIN_USER=admin ADMIN_PASSWORD=admin
RUN $JBOSS_HOME/bin/add-user.sh -u "$ADMIN_USER" -p "$ADMIN_PASSWORD" --silent

USER jboss
EXPOSE 8080 9990
CMD ["/opt/jboss/wildfly/bin/standalone.sh","-b","0.0.0.0","-bmanagement","0.0.0.0"]
