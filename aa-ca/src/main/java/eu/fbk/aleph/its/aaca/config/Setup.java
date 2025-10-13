package eu.fbk.aleph.its.aaca.config;

import com.ibm.jgroupsig.GrpKey;
import com.ibm.jgroupsig.PS16;
import eu.fbk.aleph.its.aaca.services.etsi103097.RequestEaCertificate;
import eu.fbk.aleph.its.aaca.services.etsi103097.RequestRaCertificate;
import eu.fbk.aleph.its.aaca.utils.constants.ConfigConstants;
import jakarta.annotation.PostConstruct;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.dto.RequestCertificateDto;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

@Startup
@Singleton
public class Setup {

    private static final Logger LOGGER = Logger.getLogger(Setup.class);

    private static final int SWEDEN = 752;

    static EtsiTs103097Certificate authorizationCACertificate;
    private static EtsiTs103097Certificate rootAuthorityCertificate;

    private static EtsiTs103097Certificate[] authorizationCAChain;
    private static EtsiTs103097Certificate[] enrollmentCAChain;

    private static CertStore enrolCACertStore;

    private static ETSITS102941MessagesCaGenerator messagesCaGenerator;
    private static AlgorithmIndicator signAlg;
    private static BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encAlg;
    private static Ieee1609Dot2CryptoManager cryptoManager;

    private static KeyPair authCredentialSigningKeys;
    private static KeyPair authCredentialEncryptionKeys;

    private static EtsiTs103097Certificate enrollmentAuthorityCertificate;
    private static CertStore trustStore;
    private static ETSIAuthorizationTicketGenerator etsiAuthorizationTicketGenerator;

    private static final ConcurrentHashMap<GrpKey, PS16> groupKeyToGroupMap = new ConcurrentHashMap<>();

    private static PS16 aaGroupIssuer;

    @PostConstruct
    public void init() throws Exception {

        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        signAlg = PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;
        encAlg = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;

        authCredentialSigningKeys = Setup.cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        authCredentialEncryptionKeys = Setup.cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(
                Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager,
                HashAlgorithm.sha256,
                Signature.SignatureChoices.ecdsaNistP256Signature,
                false
        );

        aaGroupIssuer = new PS16();
        aaGroupIssuer.setup();
        groupKeyToGroupMap.put(aaGroupIssuer.getGrpKey(), aaGroupIssuer);

        Client client = ClientBuilder.newClient();

        Ieee1609Dot2CryptoManager cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        RequestCertificateDto request = new RequestCertificateDto(
                "testaa.test.com",
                15,
                SWEDEN,
                1,
                3,
                encodeKey(authCredentialSigningKeys.getPublic()),
                encodeKey(authCredentialEncryptionKeys.getPublic())
        );

        authorizationCACertificate = runWithRetry(
                "authorization CA certificate",
                () -> requestAaCertSignature(request),
                Objects::nonNull // Success condition: certificate is not null
        );

        LOGGER.info("Authorization CA certificate: " + authorizationCACertificate);

        RequestRaCertificate requestRaCertificate = runWithRetry(
                "root authority certificate",
                RequestRaCertificate::new,
                eac -> eac.getRaCertificate() != null
        );

        rootAuthorityCertificate = requestRaCertificate.getRaCertificate();
        LOGGER.info("Root authority certificate: " + rootAuthorityCertificate);

        etsiAuthorizationTicketGenerator = new ETSIAuthorizationTicketGenerator(cryptoManager);

        rootAuthorityCertificate = requestRaCertificate.getRaCertificate();
        LOGGER.info("Root authority certificate: " + rootAuthorityCertificate);

        trustStore = messagesCaGenerator.buildCertStore(
                new EtsiTs103097Certificate[]{
                        rootAuthorityCertificate
                });
        authorizationCAChain = new EtsiTs103097Certificate[]{authorizationCACertificate, rootAuthorityCertificate};

        etsiAuthorizationTicketGenerator = new ETSIAuthorizationTicketGenerator(cryptoManager);

        client.close();
    }

    private <T> T runWithRetry(String operationName, Callable<T> supplier, Predicate<T> successCondition) throws Exception {
        // Define a retry policy: handle any Exception, wait 5 seconds between attempts.
        RetryPolicy<T> retryPolicy = new RetryPolicy<T>()
                .handle(Exception.class)
                .withDelay(Duration.ofSeconds(5));

        // Execute the supplier using Failsafe and the defined retry policy.
        T result = Failsafe.with(retryPolicy).get(() -> {
            LOGGER.info("Attempting to retrieve " + operationName + "...");
            // Call the operation.
            T value = supplier.call();
            // Check if the result meets the success condition.
            if (!successCondition.test(value)) {
                // Throw an exception to trigger a retry if the condition is not met.
                throw new IllegalStateException(operationName + " not retrieved.");
            }
            // Return the successful result.
            return value;
        });
        LOGGER.info("Successfully retrieved " + operationName + ": " + result.toString());
        return result;
    }

    private static EtsiTs103097Certificate requestAaCertSignature(RequestCertificateDto request) throws BadArgumentException, IOException {
        Client client = ClientBuilder.newClient();
        Response response = client.target(ConfigConstants.DEFAULT_RA_SIGN_CERT)
                .request(MediaType.TEXT_PLAIN)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        EtsiTs103097Certificate signedCert = null;
        if (response.getStatus() == 200) {
            String hexEncodedCert = response.readEntity(String.class);
            byte[] encodedCert = Hex.decode(hexEncodedCert);
            signedCert = new EtsiTs103097Certificate(encodedCert);
        } else {
            String errorResponse = response.readEntity(String.class);
            LOGGER.error("Failed to request AA certificate signature. Status: " + response.getStatus() + ", Response: " + errorResponse);
        }
        client.close();
        return signedCert;
    }

    private String encodeKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static EtsiTs103097Certificate getAaCertificate() throws IOException, BadArgumentException {
        return authorizationCACertificate;
    }

    public static EtsiTs103097Certificate getAuthorizationCACertificate() {
        return authorizationCACertificate;
    }

    public static EtsiTs103097Certificate[] getAuthorizationCAChain() {
        return authorizationCAChain;
    }

    public static ETSITS102941MessagesCaGenerator getMessagesCaGenerator() {
        return messagesCaGenerator;
    }

    public static AlgorithmIndicator getSignAlg() {
        return signAlg;
    }

    public static BasePublicEncryptionKey.BasePublicEncryptionKeyChoices getEncAlg() {
        return encAlg;
    }

    public static Ieee1609Dot2CryptoManager getCryptoManager() {
        return cryptoManager;
    }


    public static KeyPair getAuthCredentialSigningKeys() {
        return authCredentialSigningKeys;
    }


    public static KeyPair getAuthCredentialEncryptionKeys() {
        return authCredentialEncryptionKeys;
    }


    public static ETSIAuthorizationTicketGenerator getEtsiAuthorizationTicketGenerator() {
        return etsiAuthorizationTicketGenerator;
    }

    public static CertStore getTrustStore() {
        return trustStore;
    }

    public static PS16 getAaGroupIssuer() {
        return aaGroupIssuer;
    }

    public static EtsiTs103097Certificate getEnrollmentAuthorityCertificate() {
        return enrollmentAuthorityCertificate;
    }

    public static CertStore getEnrolCACertStore() {
        return enrolCACertStore;
    }

    public static void setAuthorizationCACertificate(EtsiTs103097Certificate authorizationCACertificate) {
        Setup.authorizationCACertificate = authorizationCACertificate;
    }

    public static EtsiTs103097Certificate getRootAuthorityCertificate() {
        return rootAuthorityCertificate;
    }

    public static void setRootAuthorityCertificate(EtsiTs103097Certificate rootAuthorityCertificate) {
        Setup.rootAuthorityCertificate = rootAuthorityCertificate;
    }

    public static void setAuthorizationCAChain(EtsiTs103097Certificate[] authorizationCAChain) {
        Setup.authorizationCAChain = authorizationCAChain;
    }

    public static EtsiTs103097Certificate[] getEnrollmentCAChain() {
        return enrollmentCAChain;
    }

    public static void setEnrollmentCAChain(EtsiTs103097Certificate[] enrollmentCAChain) {
        Setup.enrollmentCAChain = enrollmentCAChain;
    }

    public static void setEnrolCACertStore(CertStore enrolCACertStore) {
        Setup.enrolCACertStore = enrolCACertStore;
    }

    public static void setMessagesCaGenerator(ETSITS102941MessagesCaGenerator messagesCaGenerator) {
        Setup.messagesCaGenerator = messagesCaGenerator;
    }

    public static void setSignAlg(AlgorithmIndicator signAlg) {
        Setup.signAlg = signAlg;
    }

    public static void setEncAlg(BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encAlg) {
        Setup.encAlg = encAlg;
    }

    public static void setCryptoManager(Ieee1609Dot2CryptoManager cryptoManager) {
        Setup.cryptoManager = cryptoManager;
    }

    public static void setAuthCredentialSigningKeys(KeyPair authCredentialSigningKeys) {
        Setup.authCredentialSigningKeys = authCredentialSigningKeys;
    }

    public static void setAuthCredentialEncryptionKeys(KeyPair authCredentialEncryptionKeys) {
        Setup.authCredentialEncryptionKeys = authCredentialEncryptionKeys;
    }

    public static void setEnrollmentAuthorityCertificate(EtsiTs103097Certificate enrollmentAuthorityCertificate) {
        Setup.enrollmentAuthorityCertificate = enrollmentAuthorityCertificate;
    }

    public static void setTrustStore(CertStore trustStore) {
        Setup.trustStore = trustStore;
    }

    public static void setEtsiAuthorizationTicketGenerator(ETSIAuthorizationTicketGenerator etsiAuthorizationTicketGenerator) {
        Setup.etsiAuthorizationTicketGenerator = etsiAuthorizationTicketGenerator;
    }

    public static void setAaGroupIssuer(PS16 aaGroupIssuer) {
        Setup.aaGroupIssuer = aaGroupIssuer;
    }
}
