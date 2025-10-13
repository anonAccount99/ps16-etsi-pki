package eu.fbk.its.ca.ea.services;

import eu.fbk.its.ca.ea.config.Setup;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

/**
 * Service class responsible for processing Enrollment Certificate (EC) requests.
 * It handles the decryption and verification of incoming requests, generation
 * of new Enrollment Certificates based on the request parameters, and the
 * creation and encryption of the corresponding EC response message according
 * to ETSI ITS standards.
 */
public class GenEnrollmentCertificate {

    /**
     * Logger instance for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(GenEnrollmentCertificate.class);

    /**
     * Processes an encrypted enrollment request, generates an Enrollment Certificate,
     * and returns the encoded, encrypted enrollment response.
     *
     * @param EcRequest The deserialized EtsiTs103097DataEncryptedUnicast object representing the incoming request.
     * @return A byte array containing the encoded EtsiTs103097DataEncryptedUnicast enrollment response.
     * @throws Exception If any error occurs during decryption, verification, certificate generation, or response creation.
     */
    public static byte[] getEnrollCertificate(EtsiTs103097DataEncryptedUnicast EcRequest) throws Exception {

        LOGGER.info("Enrollment CA private key: " + Setup.getEnrollmentCAEncryptionKeys().getPrivate());
        LOGGER.info("Enrollment CA certificate: " + Setup.getEnrollmentCACert());

        Map<HashedId8, Receiver> enrollCARecipients =
                Setup.getMessagesCaGenerator().buildRecieverStore(
                    new Receiver[]{
                            new CertificateReciever(
                                    Setup.getEnrollmentCAEncryptionKeys().getPrivate(),
                                    Setup.getEnrollmentCACert()
                            )}
        );

        RequestVerifyResult<InnerEcRequest> enrollmentRequest =
                Setup.getMessagesCaGenerator().decryptAndVerifyEnrolmentRequestMessage(
                        EcRequest,
                        Setup.getEnrollCredCertStore(),
                        Setup.getTrustStore(),
                        enrollCARecipients
                );

        InnerEcRequest ecRequest = enrollmentRequest.getValue();
        CertificateSubjectAttributes ecRequestAttributes = ecRequest.getRequestedSubjectAttributes();

        ecRequest.getRequestedSubjectAttributes().getAppPermissions().getSequenceValues();

        EtsiTs103097Certificate enrolmentCredCert = Setup.getEtsiEnrollmentCredentialGenerator().genEnrollCredential(
                new String(ecRequest.getItsId(), StandardCharsets.UTF_8),
                ecRequestAttributes.getValidityPeriod(),
                ecRequestAttributes.getRegion(),
                getPermissions(ecRequest),
                ecRequestAttributes.getAssuranceLevel().getAssuranceLevel(),
                ecRequestAttributes.getAssuranceLevel().getConfidenceLevel(),
                Setup.getSignatureAlgorithm(),
                getVerificationKey(ecRequest.getPublicKeys().getVerificationKey()),
                Setup.getEnrollmentCACert(),
                Setup.getEnrollmentCASigningKeys().getPublic(),
                Setup.getEnrollmentCASigningKeys().getPrivate(),
                SymmAlgorithm.aes128Ccm,
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,
                getEncryptionKey(ecRequest.getPublicKeys().getEncryptionKey().getPublicKey())
        );

        LOGGER.info("Enrollment Credential Certificate: " + enrolmentCredCert);

        InnerEcResponse innerEcResponse = new InnerEcResponse(enrollmentRequest.getRequestHash(), EnrollmentResponseCode.ok, enrolmentCredCert);

        EtsiTs103097DataEncryptedUnicast enrollResponseMessage = Setup.getMessagesCaGenerator().genEnrolmentResponseMessage(
                new Time64(new Date()),
                innerEcResponse,
                Setup.getEnrollmentCAChain(),
                Setup.getEnrollmentCASigningKeys().getPrivate(),
                SymmAlgorithm.aes128Ccm,
                enrollmentRequest.getSecretKey());
        return enrollResponseMessage.getEncoded();
    }

    /**
     * Extracts the standard java.security.PublicKey from the PublicVerificationKey wrapper object.
     * Uses the CryptoManager to decode the embedded EC curve point based on its type.
     *
     * @param verificationKeyWrapper The PublicVerificationKey object from the request.
     * @return The corresponding java.security.PublicKey.
     * @throws Exception If decoding fails or the decoded object is not a PublicKey.
     */
    private static PublicKey getVerificationKey(PublicVerificationKey verificationKeyWrapper) throws Exception {
        EccCurvePoint verificationKeyPoint = (EccCurvePoint) verificationKeyWrapper.getValue();
        PublicVerificationKey.PublicVerificationKeyChoices verificationKeyType =
                (PublicVerificationKey.PublicVerificationKeyChoices) verificationKeyWrapper.getChoice();

        Object decodedObject = Setup.getCryptoManager().decodeEccPoint(verificationKeyType, verificationKeyPoint);

        if (!(decodedObject instanceof PublicKey verificationKey)) {
            LOGGER.error("CryptoManager.decodeEccPoint failed to return a PublicKey for the provided verification key point. Returned type: " + (decodedObject != null ? decodedObject.getClass().getName() : "null"));
            throw new Exception("Failed to decode verification key point into a PublicKey.");
        }
        return verificationKey;
    }

    /**
     * Extracts the standard java.security.PublicKey from the BasePublicEncryptionKey wrapper object.
     * Uses the CryptoManager to decode the embedded EC curve point based on its type.
     * NOTE: The parameter type should match how this method is intended to be called.
     * If called with PublicEncryptionKey, the parameter type should be updated.
     *
     * @param encryptionKeyWrapper The BasePublicEncryptionKey object (or potentially PublicEncryptionKey).
     * @return The corresponding java.security.PublicKey.
     * @throws Exception If decoding fails or the decoded object is not a PublicKey.
     */
    private static PublicKey getEncryptionKey(BasePublicEncryptionKey encryptionKeyWrapper) throws Exception {
        EccP256CurvePoint encryptionKeyPoint = (EccP256CurvePoint) encryptionKeyWrapper.getValue();
        BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encryptionKeyType =
                (BasePublicEncryptionKey.BasePublicEncryptionKeyChoices) encryptionKeyWrapper.getChoice();

        Object decodedObject = Setup.getCryptoManager().decodeEccPoint(encryptionKeyType, encryptionKeyPoint);
        if (!(decodedObject instanceof PublicKey encryptionKey)) {
            LOGGER.error("CryptoManager.decodeEccPoint failed to return a PublicKey for the provided EccP256CurvePoint. Returned type: " + (decodedObject != null ? decodedObject.getClass().getName() : "null"));
            throw new Exception("Failed to decode encryption key point into a PublicKey.");
        }
        return encryptionKey;
    }

    /**
     * Extracts the Service Specific Permissions (SSP) bytes from the InnerEcRequest.
     * Assumes the relevant SSP is the first entry in the appPermissions sequence
     * and uses the ServiceSpecificPermissions.getData() method which handles the 'opaque' case.
     *
     * @param ecRequest The InnerEcRequest containing the permissions.
     * @return The SSP as a byte array.
     * @throws Exception If permissions are missing, have an unexpected format, or are not 'opaque'.
     */
    private static byte[] getPermissions(InnerEcRequest ecRequest) throws Exception {
        CertificateSubjectAttributes ecRequestAttributes = ecRequest.getRequestedSubjectAttributes();
        if (ecRequestAttributes == null) {
            LOGGER.error("InnerEcRequest is missing CertificateSubjectAttributes.");
            throw new Exception("Missing CertificateSubjectAttributes in request.");
        }

        SequenceOfPsidSsp sequenceOfPsidSsp = ecRequestAttributes.getAppPermissions();
        if (sequenceOfPsidSsp == null) {
            LOGGER.warn("AppPermissions (SequenceOfPsidSsp) is null in the request.");
            throw new Exception("Missing required AppPermissions in Enrollment Request.");
        }

        COEREncodable[] sequenceValues = sequenceOfPsidSsp.getSequenceValues();
        if (sequenceValues == null || sequenceValues.length == 0) {
            LOGGER.warn("AppPermissions sequence (SequenceOfPsidSsp) contains no values.");
            throw new Exception("AppPermissions sequence is empty in Enrollment Request.");
        }

        COEREncodable firstSequenceValue = sequenceValues[0];
        if (!(firstSequenceValue instanceof PsidSsp psidSsp)) {
            LOGGER.error("First element in AppPermissions sequence is not a PsidSsp: " + firstSequenceValue.getClass().getName());
            throw new Exception("Invalid structure in AppPermissions sequence, expected PsidSsp.");
        }

        ServiceSpecificPermissions ssp = psidSsp.getSSP();
        if (ssp == null) {
            LOGGER.error("PsidSsp object contains null ServiceSpecificPermissions for PSID: " + psidSsp.getPsid());
            throw new Exception("Missing ServiceSpecificPermissions within PsidSsp.");
        }

        byte[] permissions = ssp.getData();

        if (permissions == null) {
            LOGGER.error("ServiceSpecificPermissions type was not 'opaque'. Actual type: " + ssp.getType());
            throw new Exception("SSP type was not 'opaque' as expected for enrollment permissions.");
        }

        if (permissions.length == 0) {
            LOGGER.warn("Extracted opaque SSP bytes are empty.");
        }

        LOGGER.info("Successfully extracted opaque SSP bytes using ssp.getData(): " + Hex.toHexString(permissions));
        return permissions;
    }
}
