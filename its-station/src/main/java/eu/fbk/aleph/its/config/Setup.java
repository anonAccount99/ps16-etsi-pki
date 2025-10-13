package eu.fbk.aleph.its.config;

import com.ibm.jgroupsig.GrpKey;
import com.ibm.jgroupsig.MemKey;
import com.ibm.jgroupsig.PS16;
import eu.fbk.aleph.its.domain.authorization.GroupJoin;
import eu.fbk.aleph.its.domain.root.RequestRaCertificate;
import eu.fbk.aleph.its.domain.authorization.RequestAaCertificate;
import eu.fbk.aleph.its.domain.authorization.AuthorizationCredentials;
import eu.fbk.aleph.its.domain.enrollment.EnrollmentCredentials;
import eu.fbk.aleph.its.domain.enrollment.RequestEaCertificate;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.groupsig.cert.AACert;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.jboss.logging.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Callable;
import java.util.function.Predicate;

import static java.lang.Thread.sleep;

/**
 * The Setup class is responsible for initializing the cryptographic components and retrieving certificates needed
 * for the application's secure communications. It establishes connections to certificate authorities and generates
 * required certificate chains for enrollment and authorization processes.
 *
 * <p>This class demonstrates the use of a retry mechanism to handle certificate retrieval operations. It relies on
 * external components such as the crypto manager, certificate generators, and Failsafe for retry policies.
 *
 * <p>Note: Documentation comments are provided outside the function bodies as requested.
 */

public class Setup {

    private static final Logger LOGGER = Logger.getLogger(Setup.class);

    private static CertStore trustStore;
    private static CertStore authTicketCertStore;
    private static EtsiTs103097Certificate[] authorizationCAChain;
    private static EtsiTs103097Certificate[] enrollmentCAChain;

    private static ETSITS102941MessagesCaGenerator messagesCaGenerator;
    private static AlgorithmIndicator signAlg;
    private static BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encAlg;
    private static Ieee1609Dot2CryptoManager cryptoManager;
    private static Ieee1609Dot2CryptoManager groupCryptoManager;

    private static EtsiTs103097Certificate rootAuthorityCertificate;
    private static EtsiTs103097Certificate enrollmentAuthorityCertificate;
    private static AACert authorizationAuthorityCertificate;

    private MemKey userMemKey;
    private PS16 userGroup;

    private static EnrollmentCredentials enrollmentCredentials;

    private static AuthorizationCredentials authorizationCredentials;

    private static ETSISecuredDataGenerator securedMessageGenerator;

    /**
     * Initializes the cryptographic components and retrieves the necessary certificates.
     * <p>
     * This method sets up the crypto manager, defines the signing algorithm, and initializes the certificate
     * generator. It then retrieves the root authority certificate, the enrollment authority certificate, and the
     * enrollment certificate using a retry mechanism. Finally, it logs the retrieved certificates and builds the
     * trust store.
     *
     * @throws Exception if any certificate retrieval or initialization fails
     */

    public void init() throws Exception {
        sleep(10000); // Wait for the CA to be up
        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        signAlg = PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;
        encAlg = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(
                Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager,
                HashAlgorithm.sha256,
                Signature.SignatureChoices.ecdsaNistP256Signature,
                false
        );

        RequestRaCertificate requestRaCertificate = runWithRetry(
                "enrollment authority certificate",
                RequestRaCertificate::new,
                eac -> eac.getRaCertificate() != null
        );
        rootAuthorityCertificate = requestRaCertificate.getRaCertificate();
        LOGGER.info("Root authority certificate: " + rootAuthorityCertificate);

        RequestEaCertificate requestEaCertificate = runWithRetry(
                "enrollment authority certificate",
                RequestEaCertificate::new,
                eac -> eac.getEaCertificate() != null
        );

        enrollmentAuthorityCertificate = requestEaCertificate.getEaCertificate();
        LOGGER.info("Enrollment authority certificate: " + enrollmentAuthorityCertificate);

        trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{rootAuthorityCertificate});
        enrollmentCAChain = new EtsiTs103097Certificate[]{requestEaCertificate.getEaCertificate(), rootAuthorityCertificate};

        enrollmentCredentials = runWithRetry(
                "enrollment certificate",
                EnrollmentCredentials::new,
                rec -> rec.getEnrollmentCertificate() != null
        );

        LOGGER.info("Enrollment Certificate: " + enrollmentCredentials.getEnrollmentCertificate());

        // Request the authorization CA certificate

        RequestAaCertificate requestAaCertificate = runWithRetry(
                "authorization CA certificate",
                RequestAaCertificate::new,
                aac -> aac.getAaCertificate() != null
        );

        authorizationAuthorityCertificate = requestAaCertificate.getAaCertificate();
        authorizationCAChain = new EtsiTs103097Certificate[]{authorizationAuthorityCertificate, rootAuthorityCertificate};

        authorizationCredentials = runWithRetry(
                "authorization ticket",
                AuthorizationCredentials::new,
                at -> at.getAuthorizationTicket() != null
        );
        LOGGER.info("Auth Ticket: " + authorizationCredentials.getAuthorizationTicket());

        // LOGGER.info("Group Member Secret Key: " + ps16MemberSecretKey);

        // Generate the group member secret key without retry
        GroupJoin groupJoin = new GroupJoin();
        PS16 group = groupJoin.getGroupUser();
        MemKey memKey = groupJoin.getMemKey();

        this.userGroup = group;
        this.userMemKey = memKey;

        securedMessageGenerator =
                new ETSISecuredDataGenerator(
                        ETSISecuredDataGenerator.DEFAULT_VERSION,
                        cryptoManager,
                        HashAlgorithm.sha256,
                        Signature.SignatureChoices.ecdsaNistP256Signature
                );

        authTicketCertStore = securedMessageGenerator.buildCertStore(
                new EtsiTs103097Certificate[]{
                        rootAuthorityCertificate,
                        authorizationAuthorityCertificate
                }
        );

        /*

        byte[] payload = Hex.decode("010203040506");
        DenmGeneratorBenchmark.registerContext(userGroup, memKey, payload);

        Options opt = new OptionsBuilder()
                .include(DenmGeneratorBenchmark.class.getSimpleName())
                .forks(0)
                .warmupIterations(5)
                .measurementIterations(10)
                .build();

        new Runner(opt).run().forEach(r -> LOGGER.info(r.getPrimaryResult()));



        DenmGenerator denmGenerator = new DenmGenerator(
                group,
                memKey
        );

        EtsiTs103097DataSigned denm = denmGenerator.getDENMessage();

        LOGGER.info(ANSI_GREEN + "Verify result: " +
                securedMessageGenerator.verifySignedData(
                        denm,
                        group
                )
        );




        eu.fbk.aleph.its.domain.denm.transmission.groupsig.DenmGenerator denmGenerator = new DenmGenerator(
                group,
                memKey
        );

        LOGGER.info("Generated DENM: " + denmGenerator.getDENMessage());

        // ==============================================================================

        eu.fbk.aleph.its.domain.denm.reception.groupsig.DenmReceiver receiver =
                new eu.fbk.aleph.its.domain.denm.reception.groupsig.DenmReceiver(
                        group,
                        memKey
                );

        receiver.start();
        LOGGER.info("DENM receiver started. Waiting for messages...");

        eu.fbk.aleph.its.domain.denm.transmission.groupsig.DenmTransmitter denmTransmitter =
                new eu.fbk.aleph.its.domain.denm.transmission.groupsig.DenmTransmitter();

        String actionId = generateActionId();
        denmTransmitter.triggerNewEvent(
                actionId,
                group,
                memKey
        );
        LOGGER.info("Trigger response: " + actionId);

        sleep(2000);

        denmTransmitter.updateEvent(
                actionId,
                group,
                memKey
        );
        LOGGER.info("Update response: " + actionId);

        sleep(2000);

        denmTransmitter.cancelEvent(actionId);
        LOGGER.info("Cancel response: " + actionId);
        LOGGER.info("Setup completed successfully.");

        Thread.currentThread().join();
        */
    }

    private static String generateActionId() {
        // Use timestamp to guarantee uniqueness
        return "event-" + Instant.now().toEpochMilli();
    }

    /**
     * Executes the given Callable with a blocking, indefinite retry policy.
     * <p>
     * The method attempts to execute the provided supplier until a valid result is obtained based on the given
     * success condition. A retry policy is applied to catch and handle any exceptions, introducing a delay between attempts.
     *
     * @param operationName a descriptive name for the operation used for logging purposes
     * @param supplier a Callable that performs the operation
     * @param successCondition a Predicate used to verify that the result is valid
     * @param <T> the type of the result returned by the supplier
     * @return the successfully retrieved result
     * @throws Exception if interrupted or another unrecoverable error occurs during the operation
     */
    private <T> T runWithRetry(String operationName, Callable<T> supplier, Predicate<T> successCondition) throws Exception {
        RetryPolicy<T> retryPolicy = new RetryPolicy<T>()
                .handle(Exception.class)
                .withDelay(Duration.ofSeconds(5));

        T result = Failsafe.with(retryPolicy).get(() -> {
            LOGGER.info("Attempting to retrieve " + operationName + "...");
            T value = supplier.call();
            if (!successCondition.test(value)) {
                throw new IllegalStateException(operationName + " not retrieved.");
            }
            return value;
        });

        LOGGER.info("Successfully retrieved " + operationName + ": " + result.toString());
        return result;
    }

    /**
     * Retrieves the enrollment authority certificate.
     *
     * @return the enrollment authority certificate
     */
    public static EtsiTs103097Certificate getEnrollmentAuthorityCertificate() {
        return enrollmentAuthorityCertificate;
    }

    public static EtsiTs103097Certificate getAuthorizationAuthorityCertificate() {
        return authorizationAuthorityCertificate;
    }

    public static CertStore getTrustStore() {
        return trustStore;
    }

    public static EtsiTs103097Certificate[] getEnrollmentCAChain() {
        return enrollmentCAChain;
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

    public static EtsiTs103097Certificate getRootAuthorityCertificate() {
        return rootAuthorityCertificate;
    }
    
    public static CertStore getAuthTicketCertStore() {
        return authTicketCertStore;
    }

    public static ETSISecuredDataGenerator getSecuredMessageGenerator() {
        return securedMessageGenerator;
    }

    public static EnrollmentCredentials getEnrollmentCredentials() {
        return enrollmentCredentials;
    }

    public static AuthorizationCredentials getAuthorizationCredentials() {
        return authorizationCredentials;
    }

    public MemKey getUserMemKey() {
        return userMemKey;
    }

    public PS16 getUserGroup() {
        return userGroup;
    }
}