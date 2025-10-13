package eu.fbk.its.ca.ea.services.groupsig;

import eu.fbk.its.ca.ea.config.Setup;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageProcessingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.groupsig.authorizationvalidation.GroupAuthorizationValidationRequest;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.Map;

public class GenAuthorizationValidation {
    public static byte[] getAuthorizationValidation(EtsiTs103097DataEncryptedUnicast authValRequest) throws BadArgumentException, GeneralSecurityException, IOException, MessageParsingException, SignatureVerificationException, DecryptionFailedException, MessageProcessingException {
        Map<HashedId8, Receiver> enrolCARecipients =
                Setup.getMessagesCaGenerator().buildRecieverStore(
                        new Receiver[] {
                                new CertificateReciever(
                                        Setup.getEnrollmentCAEncryptionKeys().getPrivate(),
                                        Setup.getEnrollmentCACert()
                                )
                        });

        RequestVerifyResult<GroupAuthorizationValidationRequest> authorizationValidationRequestVerifyResult =
                Setup.getMessagesCaGenerator().decryptAndVerifyGroupAuthorizationValidationRequestMessage(
                        authValRequest,
                        Setup.getAuthCACertStore(),
                        Setup.getTrustStore(),
                        enrolCARecipients
                );

        //TODO: the subjectAttributes should be checked
        AuthorizationValidationResponse authorizationValidationResponse = new AuthorizationValidationResponse(
                authorizationValidationRequestVerifyResult.getRequestHash(),
                AuthorizationValidationResponseCode.ok,
                authorizationValidationRequestVerifyResult.getValue().getSharedGroupRequest().getRequestedSubjectAttributes()
        );

        EtsiTs103097DataEncryptedUnicast authorizationValidationResponseMessage = Setup.getMessagesCaGenerator().genAuthorizationValidationResponseMessage(
                new Time64(new Date()), // generation Time
                authorizationValidationResponse,
                Setup.getEnrollmentCAChain(), // EA signing chain
                Setup.getEnrollmentCASigningKeys().getPrivate(), // EA signing private key
                SymmAlgorithm.aes128Ccm, // Encryption algorithm used.
                authorizationValidationRequestVerifyResult.getSecretKey() // The symmetric key generated in the request.
        );

        return authorizationValidationResponseMessage.getEncoded();

    }
}
