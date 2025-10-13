package eu.fbk.its.ca.ea.config;

import eu.fbk.its.ca.ea.services.RequestAaCertificate;
import jakarta.annotation.PostConstruct;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.dto.RequestCertificateDto;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.groupsig.cert.AACert;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

import static eu.fbk.its.ca.ea.utils.Com.runWithRetry;

/**
 * EJB Singleton responsible for initializing cryptographic materials and configurations
 * for the Enrollment Authority (EA) service on application startup.
 * It fetches the Root CA certificate, requests the EA certificate from the Root CA,
 * generates keys, and sets up necessary cryptographic managers and certificate stores.
 * Includes retry logic for robust initialization against transient network issues.
 */
@Startup
@Singleton
public class Setup {

    /**
     * Logger instance for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(Setup.class);

    /**
     * ISO 3166-1 numeric code for Sweden.
     */
    private static final int SWEDEN = 752;
    /**
     * Default URL for the Root CA's certificate signing endpoint.
     * Can be overridden by the system property DEFAULT_ROOT_CA_URL_CERT_SIGN.
     */
    static final String DEFAULT_RA_CA_URL = "http://root-ca:8080/root/api";
    static final String DEFAULT_RA_CERTIFICATE_URL = DEFAULT_RA_CA_URL + "/certificate";
    static final String DEFAULT_RA_SIGN_CERT = DEFAULT_RA_CA_URL + "/certificate-sign";

    static final String DEFAULT_AA_CA_URL = "http://aa-ca:8080/aa/api";
    static final String DEFAULT_AA_CERTIFICATE_URL = DEFAULT_AA_CA_URL + "/certificate";

    static EtsiTs103097Certificate[] authorizationCAChain;

    static CertStore authCredCertStore;

    /**
     * Key pair used by the EA for signing operations (e.g., signing responses).
     */
    static KeyPair enrollmentCASigningKeys;
    /**
     * Key pair used by the EA for encryption operations (e.g., decrypting requests).
     */
    static KeyPair enrollmentCAEncryptionKeys;

    /**
     * The chosen signature algorithm for generating keys and signing.
     */
    static Signature.SignatureChoices signatureAlgorithm;

    /**
     * Certificate store potentially holding enrollment credentials (initialized with EA chain).
     */
    static CertStore enrollCredCertStore;
    /**
     * Certificate store holding trusted Root CA certificates.
     */
    static CertStore trustStore;

    /**
     * The Root CA certificate fetched during initialization.
     */
    static EtsiTs103097Certificate rootCACert;
    /**
     * The Authorization Authority (AA) CA certificate (declared but not initialized here).
     */
    static EtsiTs103097Certificate authorizationCACert;
    /**
     * The Enrollment Authority (EA) certificate obtained from the Root CA during initialization.
     */
    static EtsiTs103097Certificate enrollmentCACert;

    static CertStore authCACertStore;

    /**
     * Generator utility for creating ETSI Enrollment Credentials.
     */
    static ETSIEnrollmentCredentialGenerator etsiEnrollmentCredentialGenerator;

    /**
     * Certificate chain for the Enrollment Authority (EA -> Root CA).
     */
    static EtsiTs103097Certificate[] enrollmentCAChain;
    /**
     * Certificate chain for Enrollment Credentials (declared but not initialized here).
     */
    static EtsiTs103097Certificate[] enrollmentCredCertChain;

    /**
     * Cryptographic manager instance providing core crypto operations (IEEE 1609.2 focused).
     */
    static Ieee1609Dot2CryptoManager cryptoManager;

    /**
     * Generator utility for creating ETSI TS 102 941 messages (e.g., enrollment responses).
     */
    static ETSITS102941MessagesCaGenerator messagesCaGenerator;

    /**
     * Initialization method executed after EJB creation and dependency injection.
     * Sets up cryptographic keys, certificates, managers, and stores required by the EA service.
     * Uses retry logic to fetch certificates from the Root CA.
     *
     * @throws Exception if initialization fails after retries or due to other errors.
     */
    @PostConstruct
    public void init() throws Exception {

        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        etsiEnrollmentCredentialGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager);

        signatureAlgorithm = Signature.SignatureChoices.ecdsaNistP256Signature;

        enrollmentCASigningKeys = cryptoManager.generateKeyPair(signatureAlgorithm);
        enrollmentCAEncryptionKeys = cryptoManager.generateKeyPair(signatureAlgorithm);

        rootCACert = runWithRetry(
                "root CA certificate",
                () -> getRootCert(DEFAULT_RA_CERTIFICATE_URL),
                Objects::nonNull,
                LOGGER
        );

        LOGGER.info("Root CA: " + rootCACert);

        RequestCertificateDto request = new RequestCertificateDto(
                "testea.test.com", // Subject CN for the EA certificate
                15,               // Validity years
                SWEDEN,           // Region code
                1,                // Assurance level
                3,                // Confidence level
                encodeKey(enrollmentCASigningKeys.getPublic()), // EA's public signing key (Base64)
                encodeKey(enrollmentCAEncryptionKeys.getPublic()) // EA's public encryption key (Base64)
        );

        enrollmentCACert = runWithRetry(
                "enrollment CA certificate",
                () -> requestEaCertSignature(DEFAULT_RA_SIGN_CERT, request),
                Objects::nonNull,
                LOGGER
        );

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(
                Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager,
                HashAlgorithm.sha256,
                Signature.SignatureChoices.ecdsaNistP256Signature,
                false // Use compressed EC points
        );

        enrollmentCAChain = new EtsiTs103097Certificate[]{enrollmentCACert, rootCACert};
        enrollCredCertStore = messagesCaGenerator.buildCertStore(enrollmentCAChain);

        RequestAaCertificate requestAaCertificate = runWithRetry(
                "authorization CA certificate",
                RequestAaCertificate::new,
                aac -> aac.getAaCertificate() != null,
                LOGGER
        );

        authorizationCACert = requestAaCertificate.getAaCertificate();
        authorizationCAChain = new EtsiTs103097Certificate[]{authorizationCACert, rootCACert};
        authCACertStore = messagesCaGenerator.buildCertStore(authorizationCAChain);

        trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{rootCACert});
    }


    /**
     * Fetches the Root CA certificate from the specified URL.
     *
     * @param rootCaUrlCert The URL endpoint to retrieve the Root CA certificate from.
     * @return The fetched Root CA certificate as an EtsiTs103097Certificate object, or null if fetching failed.
     * @throws BadArgumentException If the certificate data is invalid.
     * @throws IOException          If a communication error occurs.
     */
    private static EtsiTs103097Certificate getRootCert(String rootCaUrlCert) throws BadArgumentException, IOException {
        Client client = ClientBuilder.newClient();
        Response rootCaResponse = client.target(rootCaUrlCert)
                .request(MediaType.TEXT_PLAIN)
                .get();
        EtsiTs103097Certificate fetchedCert = null;
        if (rootCaResponse.getStatus() == 200) {
            byte[] encodedCert = rootCaResponse.readEntity(byte[].class);
            fetchedCert = new EtsiTs103097Certificate(encodedCert);
        } else {
            String errorResponse = rootCaResponse.readEntity(String.class);
            LOGGER.error("Failed to retrieve Root CA certificate. Status: " + rootCaResponse.getStatus() + ", Response: " + errorResponse);
        }
        client.close();
        return fetchedCert;
    }

    /**
     * Sends a request to the Root CA to sign and issue the EA certificate.
     *
     * @param rootCaUrlCertSign The URL endpoint of the Root CA's signing service.
     * @param request           The DTO containing the details for the EA certificate request.
     * @return The signed EA certificate as an EtsiTs103097Certificate object, or null if the request failed.
     * @throws BadArgumentException If the returned certificate data is invalid.
     * @throws IOException          If a communication error occurs.
     */
    private static EtsiTs103097Certificate requestEaCertSignature(String rootCaUrlCertSign, RequestCertificateDto request) throws BadArgumentException, IOException {
        Client client = ClientBuilder.newClient();
        Response response = client.target(rootCaUrlCertSign)
                .request(MediaType.TEXT_PLAIN)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        EtsiTs103097Certificate signedCert = null;
        if (response.getStatus() == 200) {
            String hexEncodedCert = response.readEntity(String.class);
            byte[] encodedCert = Hex.decode(hexEncodedCert);
            signedCert = new EtsiTs103097Certificate(encodedCert);
        } else {
            String errorResponse = response.readEntity(String.class);
            LOGGER.error("Failed to request EA certificate signature. Status: " + response.getStatus() + ", Response: " + errorResponse);
        }
        client.close();
        return signedCert; // Return signed cert (or null)
    }

    static public EtsiTs103097Certificate requestAaCert() {
        Client client = ClientBuilder.newClient();
        EtsiTs103097Certificate retval = null;
        try {
            Response response = client.target(Setup.DEFAULT_AA_CERTIFICATE_URL)
                    .request(MediaType.TEXT_PLAIN)
                    .get();
            if (response.getStatus() == Response.Status.OK.getStatusCode()) {
                byte[] aaCertificateBytes = response.readEntity(byte[].class);
                retval = new EtsiTs103097Certificate(aaCertificateBytes);
                LOGGER.info("AA certificate: " + retval);
            } else {
                LOGGER.error("ERROR: could not retrieve AA certificate. HTTP status: " + response.getStatus());
            }
        } catch (Exception e) {
            LOGGER.error("ERROR: could not retrieve AA certificate.", e);

        } finally {
            client.close();
        }
        return retval;
    }

    /**
     * Encodes a public key into a Base64 string representation.
     *
     * @param key The PublicKey object to encode.
     * @return The Base64 encoded string of the key's byte representation.
     */
    private String encodeKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Static getter for the initialized EA certificate.
     *
     * @return The EtsiTs103097Certificate for this Enrollment Authority.
     */
    public static EtsiTs103097Certificate getEaCertificate() {
        return enrollmentCACert;
    }

    public static EtsiTs103097Certificate[] getAuthorizationCAChain() {
        return authorizationCAChain;
    }

    public static CertStore getAuthCredCertStore() {
        return authCredCertStore;
    }

    public static KeyPair getEnrollmentCAEncryptionKeys() {
        return enrollmentCAEncryptionKeys;
    }

    public static KeyPair getEnrollmentCASigningKeys() {
        return enrollmentCASigningKeys;
    }

    public static Signature.SignatureChoices getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public static CertStore getEnrollCredCertStore() {
        return enrollCredCertStore;
    }

    public static CertStore getTrustStore() {
        return trustStore;
    }

    public static EtsiTs103097Certificate getRootCACert() {
        return rootCACert;
    }

    public static EtsiTs103097Certificate getAuthorizationCACert() {
        return authorizationCACert;
    }

    public static EtsiTs103097Certificate getEnrollmentCACert() {
        return enrollmentCACert;
    }

    public static ETSIEnrollmentCredentialGenerator getEtsiEnrollmentCredentialGenerator() {
        return etsiEnrollmentCredentialGenerator;
    }

    public static EtsiTs103097Certificate[] getEnrollmentCAChain() {
        return enrollmentCAChain;
    }

    public static EtsiTs103097Certificate[] getEnrollmentCredCertChain() {
        return enrollmentCredCertChain;
    }

    public static ETSITS102941MessagesCaGenerator getMessagesCaGenerator() {
        return messagesCaGenerator;
    }

    public static Ieee1609Dot2CryptoManager getCryptoManager() {
        return cryptoManager;
    }

    public static CertStore getAuthCACertStore() {
        return authCACertStore;
    }

    public static void setAuthorizationCACert(EtsiTs103097Certificate authorizationCACert) {
        Setup.authorizationCACert = authorizationCACert;
    }

    public static void setAuthorizationCAChain(EtsiTs103097Certificate[] authorizationCAChain) {
        Setup.authorizationCAChain = authorizationCAChain;
    }

    public static void setAuthCredCertStore(CertStore authCredCertStore) {
        Setup.authCredCertStore = authCredCertStore;
    }

    public static void setEnrollmentCASigningKeys(KeyPair enrollmentCASigningKeys) {
        Setup.enrollmentCASigningKeys = enrollmentCASigningKeys;
    }

    public static void setEnrollmentCAEncryptionKeys(KeyPair enrollmentCAEncryptionKeys) {
        Setup.enrollmentCAEncryptionKeys = enrollmentCAEncryptionKeys;
    }

    public static void setTrustStore(CertStore trustStore) {
        Setup.trustStore = trustStore;
    }

    public static void setSignatureAlgorithm(Signature.SignatureChoices signatureAlgorithm) {
        Setup.signatureAlgorithm = signatureAlgorithm;
    }

    public static void setEnrollCredCertStore(CertStore enrollCredCertStore) {
        Setup.enrollCredCertStore = enrollCredCertStore;
    }

    public static void setRootCACert(EtsiTs103097Certificate rootCACert) {
        Setup.rootCACert = rootCACert;
    }

    public static void setEtsiEnrollmentCredentialGenerator(ETSIEnrollmentCredentialGenerator etsiEnrollmentCredentialGenerator) {
        Setup.etsiEnrollmentCredentialGenerator = etsiEnrollmentCredentialGenerator;
    }

    public static void setEnrollmentCAChain(EtsiTs103097Certificate[] enrollmentCAChain) {
        Setup.enrollmentCAChain = enrollmentCAChain;
    }

    public static void setEnrollmentCACert(EtsiTs103097Certificate enrollmentCACert) {
        Setup.enrollmentCACert = enrollmentCACert;
    }

    public static void setEnrollmentCredCertChain(EtsiTs103097Certificate[] enrollmentCredCertChain) {
        Setup.enrollmentCredCertChain = enrollmentCredCertChain;
    }

    public static void setCryptoManager(Ieee1609Dot2CryptoManager cryptoManager) {
        Setup.cryptoManager = cryptoManager;
    }

    public static void setMessagesCaGenerator(ETSITS102941MessagesCaGenerator messagesCaGenerator) {
        Setup.messagesCaGenerator = messagesCaGenerator;
    }
}