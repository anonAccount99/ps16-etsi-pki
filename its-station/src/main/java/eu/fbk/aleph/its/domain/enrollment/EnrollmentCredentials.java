package eu.fbk.aleph.its.domain.enrollment;

import eu.fbk.aleph.its.utils.constant.ConfigConstants;
import eu.fbk.aleph.its.config.Setup;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageProcessingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.*;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;

/**
 * Manages the process of requesting and obtaining an Enrollment Certificate (EC)
 * for an On-Board Unit (OBU).
 * This class handles the creation of the request message, communication with the
 * Enrollment Authority (EA), and processing of the response to extract the EC.
 */
public class EnrollmentCredentials {
    /**
     * Logger instance for this class. Note: Logger references Setup class.
     */
    private static final Logger LOGGER = Logger.getLogger(Setup.class);
    /**
     * Stores the obtained Enrollment Certificate. May be null if the process fails.
     */
    private final EtsiTs103097Certificate enrollmentCertificate;

    /**
     * Temporary public signing key pair for the enrollment credential.
     */
    private final KeyPair enrollmentCredentialSigningKeys;

    /**
     * Temporary public encryption key pair for the enrollment credential.
     */

    private final KeyPair enrollmentCredentialEncryptionKeys;

    /**
     * ISO 3166-1 numeric code for Sweden.
     */
    private static final int SWEDEN = 752;

    /**
     * Constructs an instance and initiates the enrollment certificate request process.
     * Generates temporary keys, creates and encrypts the EC request, sends it to the EA,
     * receives the response, decrypts and verifies it, and extracts the EC.
     *
     * @throws Exception if any unrecoverable error occurs during the process.
     */
    public EnrollmentCredentials() throws Exception {

        enrollmentCredentialSigningKeys = Setup.getCryptoManager().generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        enrollmentCredentialEncryptionKeys = Setup.getCryptoManager().generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        try (Client client = ClientBuilder.newClient()) {
            InnerEcRequest initialInnerEcRequest =
                    genInnerEcRequest(
                            ConfigConstants.TEST_VIN, // Using a test VIN from Setup
                            enrollmentCredentialSigningKeys.getPublic(), // Temp public signing key
                            enrollmentCredentialEncryptionKeys.getPublic(), // Temp public encryption key
                            new ValidityPeriod( // Define requested validity period
                                    new SimpleDateFormat("yyyyMMdd HH:mm:ss").parse("20181202 12:12:21"), // Start time
                                    Duration.DurationChoices.years, 25 // Duration
                            ),
                            GeographicRegion.generateRegionForCountrys(List.of(SWEDEN)), // Define region
                            new SubjectAssurance(2, 0) // Define assurance level
                    );

            EncryptResult initialEnrollRequestMessageResult = Setup.getMessagesCaGenerator().genInitialEnrolmentRequestMessage(
                    new Time64(new Date()), // Generation time
                    initialInnerEcRequest,  // Inner payload
                    enrollmentCredentialSigningKeys.getPublic(), // Key for PoP verification by EA
                    enrollmentCredentialSigningKeys.getPrivate(), // Key for PoP signature generation
                    Setup.getEnrollmentAuthorityCertificate() // EA's certificate (containing encryption key)
            );
            EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = (EtsiTs103097DataEncryptedUnicast) initialEnrollRequestMessageResult.getEncryptedData();
            byte[] encodedMessage = initialEnrolRequestMessage.getEncoded();

            Response response = client.target(ConfigConstants.DEFAULT_ENROLL_URL)
                    .request(MediaType.TEXT_PLAIN)
                    .post(Entity.entity(encodedMessage, MediaType.TEXT_PLAIN));

            enrollmentCertificate = handleResponse(response, initialEnrollRequestMessageResult);

            if (enrollmentCertificate != null) {
                LOGGER.info("Enrollment Certificate obtained successfully: " + enrollmentCertificate);
            }
        }
    }

    /**
     * Processes the HTTP response received from the Enrollment Authority.
     * If successful (HTTP 200), it decrypts and verifies the response message,
     * extracts the Enrollment Certificate, and returns it.
     *
     * @param response                       The JAX-RS Response object from the EA.
     * @param initialEnrollRequestMessageResult The EncryptResult from the initial request generation,
     * containing the symmetric key needed for decryption.
     * @return The extracted EtsiTs103097Certificate (Enrollment Certificate) or null if processing failed.
     * @throws BadArgumentException          If certificate data is invalid.
     * @throws IOException                   If a communication or encoding error occurs.
     * @throws GeneralSecurityException      If a cryptographic error occurs.
     * @throws MessageParsingException       If the response message cannot be parsed.
     * @throws SignatureVerificationException If the EA's signature on the response is invalid.
     * @throws DecryptionFailedException     If the response decryption fails.
     * @throws MessageProcessingException    If general message processing fails.
     */
    private EtsiTs103097Certificate handleResponse(Response response, EncryptResult initialEnrollRequestMessageResult) throws BadArgumentException, IOException, GeneralSecurityException, MessageParsingException, SignatureVerificationException, DecryptionFailedException, MessageProcessingException {
        EtsiTs103097Certificate extractedCert = null;
        if (response.getStatus() == 200) {
            byte[] enrollResponseMessageEncoded = response.readEntity(byte[].class);
            EtsiTs103097DataEncryptedUnicast enrollResponseMessage = new EtsiTs103097DataEncryptedUnicast(enrollResponseMessageEncoded);
            CertStore enrollCACertStore = Setup.getMessagesCaGenerator().buildCertStore(Setup.getEnrollmentCAChain());

            Map<HashedId8, Receiver> enrolCredSharedKeyReceivers = Setup.getMessagesCaGenerator().buildRecieverStore(
                    new Receiver[]{
                            new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm, initialEnrollRequestMessageResult.getSecretKey())
                    }
            );
            VerifyResult<InnerEcResponse> enrollmentResponseResult = Setup.getMessagesCaGenerator().decryptAndVerifyEnrolmentResponseMessage(
                    enrollResponseMessage,
                    enrollCACertStore, // Store containing the EA's certificate chain
                    Setup.getTrustStore(), // Trust anchor (Root CA)
                    enrolCredSharedKeyReceivers // Recipient info with the symmetric key
            );
            extractedCert = enrollmentResponseResult.getValue().getCertificate();

        } else {
            String errorResponse = response.readEntity(String.class);
            LOGGER.error("Failed to retrieve Enrollment CA Certificate. Status: " + response.getStatus());
            LOGGER.error("Error response: " + errorResponse);
        }
        return extractedCert;
    }

    /**
     * Returns the Enrollment Certificate obtained from the EA.
     *
     * @return The EtsiTs103097Certificate object, or null if the request failed.
     */
    public EtsiTs103097Certificate getEnrollmentCertificate() {
        return enrollmentCertificate;
    }

    /**
     * Standard equals method comparing based on the enrollmentCertificate field.
     */
    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        EnrollmentCredentials that = (EnrollmentCredentials) o;
        return Objects.equals(enrollmentCertificate, that.enrollmentCertificate);
    }

    /**
     * Standard hashCode method based on the enrollmentCertificate field.
     */
    @Override
    public int hashCode() {
        return Objects.hashCode(enrollmentCertificate);
    }

    /**
     * Standard toString method providing a string representation of the object.
     */
    @Override
    public String toString() {
        return "EnrollmentCredentials{" +
                "enrollmentCertificate=" + (enrollmentCertificate != null ? enrollmentCertificate.toString() : "null") +
                '}';
    }

    /**
     * Encodes a public key's raw bytes into a Base64 string.
     *
     * @param key The PublicKey to encode.
     * @return The Base64 encoded string.
     */
    private String encodeKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Generates the inner payload (InnerEcRequest) for the enrollment request.
     *
     * @param itsId               The ITS Station ID (e.g., VIN).
     * @param signKey             The public key part of the temporary signing key pair.
     * @param encKey              The public key part of the temporary encryption key pair.
     * @param enrolValidityPeriod The requested validity period for the EC.
     * @param region              The requested geographic region for the EC.
     * @param subjectAssurance    The requested subject assurance level for the EC.
     * @return The constructed InnerEcRequest object.
     * @throws Exception If parsing dates or other operations fail.
     */
    private InnerEcRequest genInnerEcRequest(
            String itsId,
            PublicKey signKey,
            PublicKey encKey,
            ValidityPeriod enrolValidityPeriod,
            GeographicRegion region,
            SubjectAssurance subjectAssurance
    ) throws Exception {
        // Generate the PublicKeys structure containing the temporary keys.
        PublicKeys publicKeys = Setup.getMessagesCaGenerator().genPublicKeys(
                Setup.getSignAlg(), // Signing algorithm indicator
                signKey,       // Verification key (public part of signing key)
                SymmAlgorithm.aes128Ccm, // Symmetric algorithm indicator
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, // Encryption key type
                encKey         // Public encryption key
        );

        // Define the application permissions requested (for certificate request service).
        PsidSsp appPermCertMan = new PsidSsp(
                SecuredCertificateRequestService, // ITS-AID for the service
                new ServiceSpecificPermissions( // Define SSP as opaque bytes
                        ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,
                        Hex.decode("0132") // Specific permission bytes (meaning defined by standard/application)
                )
        );
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        // Generate the CertificateSubjectAttributes containing all requested attributes.
        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes(
                itsId, // Use ITS ID also as hostname for CertificateId
                enrolValidityPeriod,
                region,
                subjectAssurance,
                appPermissions,
                null // No certificate issue permissions requested
        );

        // Construct and return the InnerEcRequest object.
        return new InnerEcRequest(
                itsId.getBytes(StandardCharsets.UTF_8), // ITS ID as bytes
                CertificateFormat.TS103097C131, // Specify requested certificate format
                publicKeys, // Include the generated public keys
                certificateSubjectAttributes // Include the requested attributes
        );
    }

    /**
     * Generates the CertificateSubjectAttributes structure containing details
     * requested for the new certificate.
     *
     * @param hostname             Optional hostname for the certificate ID.
     * @param validityPeriod       Requested validity period.
     * @param region               Requested geographic region (optional).
     * @param assuranceLevel       Requested subject assurance level.
     * @param appPermissions       Requested application permissions (PsidSsp array).
     * @param certIssuePermissions Requested certificate issuance permissions (optional).
     * @return The constructed CertificateSubjectAttributes object.
     * @throws Exception Potentially from underlying certificate ID creation.
     */
    private CertificateSubjectAttributes genCertificateSubjectAttributes(
            String hostname,
            ValidityPeriod validityPeriod,
            GeographicRegion region,
            SubjectAssurance assuranceLevel,
            PsidSsp[] appPermissions,
            PsidGroupPermissions[] certIssuePermissions
    ) throws Exception {

        // Log the application permissions being set.
        if (appPermissions != null) {
            for (PsidSsp appPermission : appPermissions) {
                LOGGER.info("App Permission requested: " + appPermission.toString()); // Log full PsidSsp details
            }
        }

        // Construct and return the CertificateSubjectAttributes object.
        return new CertificateSubjectAttributes(
                (hostname != null ? new CertificateId(new Hostname(hostname)) : new CertificateId()), // Create CertificateId
                validityPeriod,
                region,
                assuranceLevel,
                new SequenceOfPsidSsp(appPermissions), // Wrap app permissions in sequence
                (certIssuePermissions != null ? new SequenceOfPsidGroupPermissions(certIssuePermissions) : null) // Wrap cert issue permissions if present
        );
    }

    public KeyPair getEnrollmentCredentialSigningKeys() {
        return enrollmentCredentialSigningKeys;
    }

    public KeyPair getEnrollmentCredentialEncryptionKeys() {
        return enrollmentCredentialEncryptionKeys;
    }
}