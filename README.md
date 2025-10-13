# PKI-GroupSig: Group Signature-Enabled PKI for C-ITS

**PKI-GroupSig** is a Java-based implementation of a Public Key Infrastructure tailored for Cooperative Intelligent Transport Systems (C-ITS). It features a multi-tier certificate authority hierarchy with support for group signatures to provide privacy-preserving authentication for vehicle communications. The project implements standard ITS security message and certificate formats from ETSI and IEEE (e.g. **ETSI TS 103 097 v1.3.1**, **ETSI TS 102 941 v1.3.1**, and **IEEE 1609.2-2016/1609.2a-2017**). It includes components for a Root Certificate Authority, an Enrollment Authority, an Authorization Authority, and an example ITS station (on-board unit) to demonstrate certificate issuance and secure message exchange. By integrating the *libgroupsig* library, the system enables group signature operations for anonymous yet verifiable messages.

## Features

* **Standards-Compliant ITS PKI** – Supports the ETSI TS 103 097 security header and certificate formats and IEEE 1609.2 specifications for vehicular communication security, ensuring interoperability with C-ITS standards.
* **Multi-Tier Certificate Authorities** – Implements a hierarchical PKI with distinct roles: a Root CA, an Enrollment CA (EA), and an Authorization CA (AA). Each CA runs as a separate service, issuing and managing different certificate types (the default service endpoints are `http://root-ca:8080/root`, `http://ea-ca:8080/ea`, and `http://aa-ca:8080/aa` for Root, EA, and AA respectively). This mirrors the trust structure defined in ETSI C-ITS security (with the Root CA as trust anchor, the EA issuing enrollment credentials, and the AA issuing authorization tickets/pseudonym certificates).
* **Group Signature Support** – Integrates the **libgroupsig** C library (via JNI) to provide group signature capabilities. Messages (e.g. CAM/DENM in C-ITS) can be signed such that individual vehicles remain anonymous while a group manager (or authorities) can still verify and, if necessary, revoke anonymity. This enhances privacy for vehicle broadcasts.
* **RESTful Certificate Services** – Exposes RESTful APIs (built with Jakarta EE JAX-RS) for certificate management. For example:

    * *Enrollment Certificate API*: Allows an ITS station to request an enrollment certificate from the EA (e.g. `POST /ea/api/enrollment-certificate`). The station’s unique ID (e.g. a vehicle identifier) is used to obtain a long-term credential signed by the EA.
    * *Authorization Ticket API*: Allows an enrolled station to request pseudonym certificates (authorization tickets) from the AA (e.g. `POST /aa/api/authorization-ticket`), presenting its enrollment cert as proof of legitimacy.
    * *CA Certificate Retrieval*: Endpoints to retrieve the public certificates of the Root CA, EA, and AA (e.g. `GET /root/api/certificate`, etc.) so that stations and other entities can obtain trust anchors and intermediate CA certs.
* **ITS Station Simulator** – Includes an **ITS Station** component (simulated on-board unit) that interacts with the PKI. On startup, the station automatically requests an enrollment certificate from the EA and uses it to obtain an authorization certificate from the AA (with retry logic to wait for services to be available). It can then generate and broadcast signed **DENM (Decentralized Environmental Notification Message)** messages. A provided `DenmReceiver` listens on a defined port to receive and verify incoming DENMs, demonstrating end-to-end operation.
* **Configurable and Extensible** – Uses the flexibility of Java and WildFly application server to allow configuration of cryptographic algorithms and trust stores. It relies on BouncyCastle for cryptographic primitives and encoding (COER/ASN.1) of certificates. The system is modular, with a common library (`c2c-common-groupsig`) that can be reused or extended for other ITS applications.
* **Containerized Deployment** – All components are Dockerized for easy setup. Each CA and the station come with a Dockerfile based on JBoss WildFly 26/36 (Java EE 8/Jakarta EE 10 on JDK 21). A **docker-compose** configuration is provided to orchestrate the services, ensuring they start in the correct order (Root CA → EA → AA → ITS station) and network together. This allows quick deployment of the entire PKI and test station stack in isolated containers.

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
* **Environment Variables:** The Docker Compose file defines some env variables (like WildFly admin credentials). You can also pass in environment variables to tweak configurations; for example, if the code were designed to read a specific env var for overriding the default URLs or cryptographic settings (not explicitly implemented in this version, but could be extended).
* **Logging:** Logging levels can be adjusted via standard Java logging config or WildFly configuration. By default, important actions (certificate issuance, requests, errors) are logged to console.

## Project Structure

The repository is organized into multiple modules, each in its own directory under the root:

* **c2c-common-groupsig/** – Core library containing the implementations of data structures and crypto functions according to ETSI TS 103 097 / IEEE 1609.2. This includes certificate formats, message signing and verification, encoders/decoders, and utility classes. (It’s essentially an updated version of a C-ITS security library with group signature support added.)
* **root-ca/** – The Root Certificate Authority service. This module produces a WAR that, when deployed, runs a service listening (by default) at context path `/root`. It holds the Root CA key pair and issues certificates to subordinate CAs. Key contents:

    * *Services & API:* Contains a `RootCert` resource (for retrieving the root certificate) and a `SignCaCert` resource (used by subordinate CAs to get their CSR signed by the root). The `Setup` singleton bean in this module likely generates the Root CA key on first run (or loads a preset one) and registers it for use.
    * *Dockerfile:* Builds the war and sets up the environment for this service.
* **ea-ca/** – The Enrollment Authority module. WAR runs at context `/ea`. Responsible for issuing **Enrollment Certificates** to vehicles (ITS stations). Key contents:

    * `EnrollmentCertificate` API (handles incoming requests for enrollment certs, probably expecting some identification or public key from the station and returning a signed certificate).
    * `EaCertificate` resource (for retrieving the EA’s own certificate, which is signed by the Root CA). The EA on startup likely uses `SignCaCert` from Root CA to obtain its cert if not already present.
    * Possibly an `EnrollmentVerification` API (used by AA to verify a given enrollment cert’s validity, if the workflow requires cross-checking with EA).
    * *Setup logic:* On startup, if the EA doesn’t have a valid cert, it may generate a key pair and call Root CA’s API to get signed. It then stores its certificate (for serving to others).
* **aa-ca/** – The Authorization Authority module. WAR at context `/aa`. Issues **Authorization Tickets** (short-term anonymous certificates) to stations:

    * `AuthorizationTicket` API endpoint for stations to request pseudonym certificates. The station must provide its enrollment certificate (or a digest of it) as proof. The AA will typically verify that the enrollment cert was issued by a trusted EA (possibly by checking the signature using the EA’s cert or contacting the EA’s verification service). If valid, the AA issues one or more authorization certificates (which might be downloaded or pushed to the station).
    * `AaCert` resource (for retrieving the AA’s own certificate, signed by the Root CA).
    * *Setup:* Similar to EA, the AA module on startup ensures it has a certificate (signed by Root CA). It may either get signed directly by Root CA or through an intermediate (depending on PKI design, but from code it looks like Root CA signs both EA and AA). The AA’s Setup bean likely handles key generation and obtaining the cert.
* **its-station/** – The ITS Station simulator module. This is an application that acts as a vehicle’s on-board unit (OBU):

    * On startup, a `Setup` singleton bean triggers the enrollment and authorization process: it generates a vehicle key pair (if not existing), contacts the EA’s `/enrollment-certificate` API to get an enrollment cert, then uses that to call the AA’s `/authorization-ticket` API. The obtained certificates are stored (likely in memory or a simple file) via the `CertStore` from the common library.
    * Contains `DenmTransmitter` and `DenmReceiver` components (possibly as EJBs or threads). The transmitter can periodically or on-demand create a DENM message, sign it with the vehicle’s current authorization certificate (group signature or regular ECDSA depending on config), and send it via UDP broadcast on port 30000. The receiver listens on that port for any incoming DENMs from other stations and verifies them (using the certificate chain and CRL info from CAs).
    * REST endpoints: `Denm` resource (e.g., `POST /api/denm/trigger/{id}`) to allow external triggering of a DENM broadcast. This could be used to instruct the station to send a specific message (perhaps `{id}` could select different test scenarios). There is also a `Resource` class (possibly a base path ping or general endpoint). The station’s JAX-RS application is configured with base path `/api` (see `ObuConfig` class).
    * *Dockerfile:* Similar pattern to CA services – builds the station WAR, sets up libgroupsig, etc., and deploys on WildFly. The station container joins two networks in Docker: one shared with the CAs (to reach their services by name) and one separate `its-stations-net` (which could simulate an ad-hoc network for broadcasting DENMs among station containers).
* **docker-compose.yml** – Orchestration file to build and run all components together. Defines networks and service dependencies so that, for example, the EA waits for Root CA to be available before starting, etc.. This file is handy for quickly spinning up the entire demonstration PKI environment.

Other notable files and folders:

* **LICENSE.txt** – The license file for the project (AGPL-3.0).
* **README.adoc / README.md** – Documentation files (in AsciiDoc and Markdown) found in the common library and each module. (Some sub-module README files were placeholders.) This combined README (you’re reading) is synthesized from those and the code.
* **Gradle build scripts** – `build.gradle` in each module and a root `settings.gradle` that defines the multi-project structure. They configure dependencies like BouncyCastle and the libgroupsig wrapper JAR (`com.ibm.jgroupsig:1.1.0`).
* **.gitmodules** – Indicates this project was structured with Git submodules for each component in its original repository form. Each submodule corresponds to one of the directories above (root-ca, ea-ca, etc.), which were likely individual repositories (e.g., on a GitLab instance) combined here.

The codebase is logically separated by component, which makes it easier to understand each part of the system independently (e.g., one can focus on `aa-ca` to see how the AA works, etc.).
