package eu.fbk.its.ca.ea.services;

import eu.fbk.its.ca.ea.config.Setup;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.jboss.logging.Logger;

import java.util.Date;
import java.util.Map;
import java.util.Objects;

import static eu.fbk.its.ca.ea.utils.Com.runWithRetry;

public class GenEnrollmentVerification {
    static Logger LOGGER = Logger.getLogger(GenEnrollmentVerification.class);
    public static byte[] getEnrollmentVerification(EtsiTs103097DataEncryptedUnicast enrollVerRequest) throws Exception {
        Map<HashedId8, Receiver> enrolCARecipients =
                Setup.getMessagesCaGenerator().buildRecieverStore(
                        new Receiver[] {
                                new CertificateReciever(
                                        Setup.getEnrollmentCAEncryptionKeys().getPrivate(),
                                        Setup.getEnrollmentCACert()
                                )
                        });

        if(Setup.getAuthCredCertStore() == null) {
            Setup.setAuthorizationCACert(runWithRetry(
                    "authorization CA certificate",
                    Setup::requestAaCert,
                    Objects::nonNull,
                    LOGGER
            ));
            Setup.setAuthorizationCAChain(new EtsiTs103097Certificate[]{Setup.getAuthorizationCACert(), Setup.getRootCACert()});
            Setup.setAuthCredCertStore(Setup.getMessagesCaGenerator().buildCertStore(Setup.getAuthorizationCAChain()));
        }

        RequestVerifyResult<AuthorizationValidationRequest> authorizationValidationRequestVerifyResult =
                Setup.getMessagesCaGenerator().decryptAndVerifyAuthorizationValidationRequestMessage(
                        enrollVerRequest,
                        Setup.getAuthCredCertStore(), // certificate store containing certificates for auth cert.
                        Setup.getTrustStore(),
                        enrolCARecipients
                );

        AuthorizationValidationResponse authorizationValidationResponse = new AuthorizationValidationResponse(
                authorizationValidationRequestVerifyResult.getRequestHash(),
                AuthorizationValidationResponseCode.ok,
                authorizationValidationRequestVerifyResult.getValue().getSharedAtRequest().getRequestedSubjectAttributes()
        );

        EtsiTs103097DataEncryptedUnicast authorizationValidationResponseMessage =
                Setup.getMessagesCaGenerator().genAuthorizationValidationResponseMessage(
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
