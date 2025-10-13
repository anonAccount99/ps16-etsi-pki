package eu.fbk.aleph.its.aaca.services.etsi103097.utils;

import eu.fbk.aleph.its.aaca.config.Setup;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.jboss.logging.Logger;

import java.security.PublicKey;

public class ParseAuthorizationRequest {
    private static final Logger LOGGER = Logger.getLogger(ParseAuthorizationRequest.class);

    public static PublicKey getVerificationKey(PublicVerificationKey verificationKeyWrapper) throws Exception {
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

    public static PublicKey getEncryptionKey(BasePublicEncryptionKey encryptionKeyWrapper) throws Exception {
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
     * Extracts the array of PsidSsp (PSID and Service Specific Permissions)
     * from the appPermissions field within the InnerAtRequest's shared data.
     *
     * @param atRequest The InnerAtRequest containing the permissions.
     * @return The PsidSsp array.
     * @throws Exception If permissions are missing or the sequence contains invalid types.
     */
    public static PsidSsp[] getPermissions(InnerAtRequest atRequest) throws Exception {
        // Navigate to the requested subject attributes within the shared part of the AT request.
        CertificateSubjectAttributes requestedAttributes = atRequest.getSharedAtRequest().getRequestedSubjectAttributes();
        if (requestedAttributes == null) {
            LOGGER.error("InnerAtRequest's SharedAtRequest is missing CertificateSubjectAttributes.");
            throw new Exception("Missing CertificateSubjectAttributes in request.");
        }

        SequenceOfPsidSsp sequenceOfPsidSsp = requestedAttributes.getAppPermissions();
        if (sequenceOfPsidSsp == null) {
            LOGGER.warn("AppPermissions (SequenceOfPsidSsp) is null in the request's attributes.");
            throw new Exception("Missing required AppPermissions in Authorization Request.");
        }

        COEREncodable[] sequenceValues = sequenceOfPsidSsp.getSequenceValues();
        if (sequenceValues == null || sequenceValues.length == 0) {
            LOGGER.warn("AppPermissions sequence (SequenceOfPsidSsp) contains no values.");
            throw new Exception("AppPermissions sequence is empty in Authorization Request.");
        }

        PsidSsp[] permissionsArray = new PsidSsp[sequenceValues.length];
        for (int i = 0; i < sequenceValues.length; i++) {
            if (!(sequenceValues[i] instanceof PsidSsp)) {
                LOGGER.error("Element " + i + " in AppPermissions sequence is not a PsidSsp: " + sequenceValues[i].getClass().getName());
                throw new Exception("Invalid structure in AppPermissions sequence, expected only PsidSsp elements.");
            }
            permissionsArray[i] = (PsidSsp) sequenceValues[i];
        }

        LOGGER.info("Successfully extracted " + permissionsArray.length + " PsidSsp entries.");
        return permissionsArray;
    }
}
