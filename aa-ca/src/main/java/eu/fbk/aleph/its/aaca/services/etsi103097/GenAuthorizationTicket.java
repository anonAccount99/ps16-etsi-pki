package eu.fbk.aleph.its.aaca.services.etsi103097;

import eu.fbk.aleph.its.aaca.config.Setup;
import eu.fbk.aleph.its.aaca.services.etsi103097.utils.ParseAuthorizationRequest;
import eu.fbk.aleph.its.aaca.services.etsi103097.utils.VerifyAuthorizationRequest;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageProcessingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.jboss.logging.Logger;

import java.util.Date;

public class GenAuthorizationTicket {

    private static final Logger LOGGER = Logger.getLogger(GenAuthorizationTicket.class);

    public static byte[] getAuthorizationTicket(EtsiTs103097DataEncryptedUnicast authRequest) throws Exception {

        RequestVerifyResult<InnerAtRequest> authVerifyResult;
        AuthorizationResponseCode authorizationResponseCode = AuthorizationResponseCode.ok;
        EtsiTs103097Certificate authorizationCredCert = null;

        try {
            // To decrypt the message and verify the external POP signature (not the inner eCSignature signed for EA CA).
            authVerifyResult = VerifyAuthorizationRequest.verifyAuthorizationRequest(authRequest);

            InnerAtRequest innerAtRequest = authVerifyResult.getValue();

            CertificateSubjectAttributes atRequestAttributes =
                    innerAtRequest.getSharedAtRequest().getRequestedSubjectAttributes();

            // TODO: (Look into) The verified and decrypted (if withPrivacy) eCSignature is retrived with
            // EcSignature ecSignature = ecSignatureVerifyResult.getValue();

            authorizationCredCert =
                    Setup.getEtsiAuthorizationTicketGenerator().genAuthorizationTicket(
                            atRequestAttributes.getValidityPeriod(),
                            atRequestAttributes.getRegion(),
                            atRequestAttributes.getAssuranceLevel(),
                            ParseAuthorizationRequest.getPermissions(innerAtRequest),
                            Setup.getSignAlg(),
                            ParseAuthorizationRequest.getVerificationKey(innerAtRequest.getPublicKeys().getVerificationKey()),
                            Setup.getAuthorizationCACertificate(),
                            Setup.getAuthCredentialSigningKeys().getPublic(),
                            Setup.getAuthCredentialSigningKeys().getPrivate(),
                            SymmAlgorithm.aes128Ccm,
                            Setup.getEncAlg(),
                            ParseAuthorizationRequest.getEncryptionKey(innerAtRequest.getPublicKeys().getEncryptionKey().getPublicKey())
                    );

            LOGGER.info("Generated authorization ticket: " + authorizationCredCert);
        } catch (BadArgumentException e) {
            LOGGER.error("Bad argument in authorization request: " + e.getMessage());
            authorizationResponseCode = AuthorizationResponseCode.its_aa_badcontenttype;
        } catch (MessageParsingException e) {
            LOGGER.error("Failed to parse authorization request: " + e.getMessage());
            authorizationResponseCode = AuthorizationResponseCode.its_aa_cantparse;
        } catch (SignatureVerificationException e) {
            LOGGER.error("Signature verification failed for authorization request: " + e.getMessage());
            authorizationResponseCode = AuthorizationResponseCode.invalidsignature;
        } catch (DecryptionFailedException e) {
            LOGGER.error("Decryption failed for authorization request: " + e.getMessage());
            authorizationResponseCode = AuthorizationResponseCode.its_aa_decryptionfailed;
        } catch (MessageProcessingException e) {
            LOGGER.error("Message processing failed for authorization request: " + e.getMessage());
            authorizationResponseCode = AuthorizationResponseCode.its_aa_badcontenttype;
        } finally {
            authVerifyResult = VerifyAuthorizationRequest.verifyAuthorizationRequest(authRequest);
        }

        InnerAtResponse innerAtResponse =
                new InnerAtResponse(
                        authVerifyResult.getRequestHash(),
                        authorizationResponseCode,
                        authorizationCredCert
        );

        EtsiTs103097DataEncryptedUnicast authResponseMessage =
                Setup.getMessagesCaGenerator().genAuthorizationResponseMessage(
                        new Time64(new Date()), // generation Time
                        innerAtResponse,
                        Setup.getAuthorizationCAChain(), // The AA certificate chain signing the message
                        Setup.getAuthCredentialSigningKeys().getPrivate(),
                        SymmAlgorithm.aes128Ccm, // Encryption algorithm used.
                        authVerifyResult.getSecretKey()// The symmetric key generated in the request.
                );

        return authResponseMessage.getEncoded();
    }

}


