# PS16-ETSI-PKI: Group Signatures for ETSI C-ITS

**PS16-ETSI-PKI** is a Java-based implementation of a Public Key Infrastructure tailored for Cooperative Intelligent Transport Systems (C-ITS). The project leverages the open source *C2C-Common* project to implement standard ITS security message and certificate formats from ETSI and IEEE (e.g. **ETSI TS 103 097 v1.3.1**, **ETSI TS 102 941 v1.3.1**, and **IEEE 1609.2-2016/1609.2a-2017**). It includes a Root Certificate Authority, an Enrollment Authority, an Authorization Authority, and an ITS station, for now only used to benchmark DENM genration and verfication. This project also leverages IBM's *libgroupsig* -- a library implementing multiple group signature schemes. In particular, we modify C2C-Common to support the generation of DEN Messages signed with *PS16* signatures -- a schema implemented in *libgroupsig*.

In `./libgroupsig_bench/` we also include benchmarking code to measure the performance of group signature generation and verification using libgroupsig.

## Libgroupsig Benchmark Execution

Run from project root:

```bash
cd libgroupsig_bench
docker build -t libgroupsig-bench .
docker run --rm -it \
  -v "$(pwd)/scripts:/app/scripts" \
  libgroupsig-bench \
  /bin/bash -c "cd /app && ./run_benchmarks.sh"
```

Results will output in `./libgroupsig_bench/scripts`. Remember to use `--platform=linux/amd64` if on a non-x86_64 host.

## PKI PoC Execution

Prerequisites: Docker and Docker Compose v2.

Run from project root:

```bash
sudo ./setup.sh
docker compose up build
```

The first command prepares the local environment and permissions. The second command builds and starts all services. Benchmark results will appear at `./benchmark-results/benchmark-results.json`. To stop the stack, press `Ctrl+C`, then run:

```bash
docker compose down
```


## Technology Stack

* **Programming Language:** Java (with some Kotlin used for testing/benchmarking). Target Java version is 21 (as used in the WildFly 36 JDK21 base image).
* **Frameworks/Containers:** Jakarta EE running on *WildFly* application server. Each PKI component is packaged as a WAR and deployed on WildFly (enabling use of EJBs, JAX-RS, etc.). The example ITS station also runs on WildFly for consistency.
* **Cryptography Libraries:** Uses **BouncyCastle** (bcprov) for cryptographic operations and certificate encoding/decoding (supporting ECDSA, AES, etc. as required by ITS standards). Also incorporates **libgroupsig** (a native C/C++ library for group signatures) for advanced cryptographic functionality. The libgroupsig Java wrapper (`com.ibm.jgroupsig:1.1.0`) is leveraged via JNI to perform group signature creation and verification.
* **Networking:** The station uses UDP sockets for message broadcast/reception (simulating V2X communication on a local network). RESTful HTTP APIs (Jakarta RESTful Web Services) are used for inter-component communication (e.g. station to CA requests).
* **Build Tool:** *Gradle* (with Gradle Wrapper). The project is organized as a multi-module Gradle build (root project `pki-groupsig` including sub-projects for each component). Gradle handles compilation and packaging of WARs.
* **Dependencies & Modules:**

    * `c2c-common-groupsig`: Core library module implementing ITS certificate/message structures and crypto utilities.
    * `root-ca`, `ea-ca`, `aa-ca`: Each is a web application module for the respective certificate authority service. They depend on the common library and provide specific REST endpoints and EJB logic for their role.
    * `its-station`: Web application for the station simulator, depending on common library and containing logic to interact with CAs and simulate message transmission.
* **Docker & OS:** Docker images are based on a lightweight Linux with required native libraries (OpenSSL, GMP, GLib2) installed for cryptographic operations. WildFly runs in standalone mode inside the containers. The Docker setup also uses a custom healthcheck (curl-based) to ensure each service is up before the dependents start.

## Installation

You can set up the project either using Docker (recommended for an out-of-the-box experience) or by building from source on your host.

### Using Docker Compose (Quick Start)

1. **Prerequisites:** Install Docker and Docker Compose on your system. Ensure you have at least Docker Engine 20.x and Compose v2 (or Docker Desktop with Compose support).
2. **Acquire the Project:** Obtain the `pki-groupsig` project files (e.g., clone the repository or unzip the provided archive). Make sure the `docker-compose.yml` is present at the project root.
3. **Build and Run:** In a terminal, navigate to the project root directory and run:

   ```bash
   docker-compose up --build
   ```

   This will build images for all components (root-ca, ea-ca, aa-ca, its-station) and start the containers. The Compose file ensures dependencies are honored (e.g., the Enrollment CA waits for Root CA to be available, etc.). The build process will also download and compile the native libgroupsig library inside the images, which may take a few minutes on first run.
4. **Verify Startup:** Docker Compose will stream the logs. Wait until all services report a **“Running”** status. Health-checks are in place, so you should see each service marked healthy in the output. Once the ITS station is running, it will attempt to register and obtain certificates from the CAs.
5. **Interact with the System:** By default, the services are only inside the Docker network (not exposed to host). To observe the system:

    * You can inspect logs for each component with `docker-compose logs <service>` (e.g., `docker-compose logs its-station`). The station’s log should show steps like requesting an enrollment cert and an authorization ticket, and eventually logging messages about DENM generation.
    * To simulate message transmission, the station periodically (or on trigger) broadcasts a DENM. If you want to run multiple station instances to see communication, you can scale the `its-station` service or run additional containers on the `its-stations-net` Docker network. Each station will listen on UDP port **30000** for incoming DENMs by default. The console logs will indicate if a station receives a message from another.
    * If needed, you can also *expose* the REST endpoints to the host by editing the `docker-compose.yml` (for example, add a port mapping like `8081:8080` under the `its-station` service to access its API from your host browser or tools). This is optional for testing the REST APIs (e.g., you could then `GET http://localhost:8081/api/certificate` to fetch the station’s current certificate or use the station’s `POST /api/denm/trigger` endpoint to force a DENM broadcast).
6. **Shutdown:** Bring down the infrastructure with `docker-compose down` when done. (Data is not persisted by default; if you restart, the CAs and station will generate fresh keys and repeat the enrollment process.)

### Building from Source (Manual Setup)

If you prefer to run the services natively (without Docker), follow these steps:

1. **Prerequisites:**

    * JDK 21 (Java 17+ might work if adjusted, but the project targets Java 21 features). Ensure `JAVA_HOME` is set accordingly.
    * Apache Maven (for building the native libgroupsig wrapper) and Gradle (optional if using the provided Gradle Wrapper).
    * C/C++ build tools: You need a compiler (gcc/g++), CMake, and development libraries for OpenSSL, GMP, and GLib2, which are required to compile *libgroupsig*.
2. **Build libgroupsig:** Clone the libgroupsig library source from GitHub (e.g., `git clone https://github.com/IBM/libgroupsig.git`) or the provided source in the project’s Docker context. Follow its instructions to build the core library (`cmake && make`) and install it on your system (`make install`). Then build and install the Java wrapper for libgroupsig (located under `src/wrappers/java/jgroupsig` in the libgroupsig project). This typically involves running `mvn install` in that directory, which will install the `com.ibm.jgroupsig` JAR to your local Maven repository.
3. **Configure WildFly (or another Java EE container):** Each CA and the station are packaged as WAR files. You can run them on WildFly or any Jakarta EE 10 compatible application server. WildFly 26+ is recommended (the same version as used in Docker). Ensure the server trusts the Root CA certificate if you plan to use HTTPS or mutual authentication (for basic operation over HTTP this may not be needed).
4. **Build the WAR files:** In the project root, use the Gradle Wrapper to compile and package all modules:

   ```bash
   ./gradlew clean build
   ```

   This will produce WAR artifacts for each module under their `build/libs` directories (e.g., `root-ca/build/libs/root-ca.war`, similarly for ea-ca, aa-ca, and its-station). Make sure the `jgroupsig` dependency was resolved (the build script expects the libgroupsig wrapper JAR in your local Maven repo; if the build fails at this dependency, revisit step 2).
5. **Deploy to Application Server:** Copy the WAR files to your application server’s deployment directory. For WildFly, you can copy each WAR to the `standalone/deployments/` folder. Start a WildFly instance for each service (on different ports or different machines/VMs) or deploy them to one WildFly instance under different context paths. By default, the context roots are set as `/root`, `/ea`, `/aa`, and (for the station) `/` or `/its` (depending on configuration). Ensure the URLs configured in the station (which default to `http://ea-ca:8080/ea` etc.) are adjusted if your deployment differs (e.g., using localhost and distinct ports). You might do this by editing the `ConfigConstants` or supplying DNS entries so that `ea-ca`, `aa-ca`, etc. resolve to the appropriate host.
6. **Operation:** Once all components are deployed and running, the behavior will be similar to the Docker setup. The station (its-station app) will on startup attempt to contact the EA and AA services at the configured URLs. Monitor the logs for messages indicating successful enrollment and authorization. You can then use the station’s REST interface or automated timers to generate DENM messages. Other stations (if deployed similarly) can receive and verify those messages.

*Note:* Manual setup is more involved and primarily recommended for development or debugging purposes. The Docker approach encapsulates all these steps and configuration, providing a quicker path to a running system.

## Configuration

Most configuration is handled internally or via environment variables in the Docker setup:

* **Service Endpoints:** The ITS station is configured by default to reach the CAs at the hostnames `root-ca`, `ea-ca`, `aa-ca` on port 8080 (with path `/root/api`, `/ea/api`, `/aa/api` respectively). In Docker, these hostnames are automatically resolved via the custom network. If you deploy outside Docker, you may need to edit these defaults (see `ConfigConstants.java`) or provide DNS/host entries so the services can find each other. Alternatively, modify the station’s configuration to point to the correct URLs of the CA services.
* **Crypto Parameters:** The project follows the algorithms mandated by the standards. ECDSA with curve secp256r1 is typically used for certificates and message signatures, and AES-CCM for encryption, etc., as per ETSI specs. These are largely fixed in the code via the common library. If needed, algorithm identifiers can be changed by using the *DefaultCryptoManager* from the library with different parameters. The libgroupsig component supports different group signature schemes (e.g., BSZ, CPY06, etc.); the specific scheme can be selected in the libgroupsig configuration (defaults may be defined in libgroupsig’s build or can be switched by calling its API in code).
* **WildFly Settings:** In Docker, WildFly is configured with an admin user (`admin:admin` by default) and deployed in standalone mode. No special ports besides 8080 (HTTP) and 9990 (management) are open. If you need to secure the services with TLS or change ports, you can adapt the Dockerfiles or WildFly configuration (standalone.xml or CLI scripts). For instance, enabling HTTPS would require adding the CA certs to the truststore and configuring an HTTPS listener.
* **Persistent Storage:** By default, certificates and keys are kept in memory or local files inside the containers. The Root CA, EA, and AA likely generate a key pair (and self-signed or cross-signed certificates) at first startup. In the current setup, these are not persisted outside the container (so each fresh start resets the PKI). For a real deployment, you would attach volumes to persist the keystores or use an external database/HSMS.
* **Logging:** Logging levels can be adjusted via standard Java logging config or WildFly configuration. By default, important actions (certificate issuance, requests, errors) are logged to console.

The codebase is logically separated by component, which makes it easier to understand each part of the system independently (e.g., one can focus on `aa-ca` to see how the AA works, etc.).
