package eu.fbk.aleph.its.aaca.services.groupsig;

import com.ibm.jgroupsig.GrpKey;
import eu.fbk.aleph.its.aaca.config.Setup;
import eu.fbk.aleph.its.aaca.services.etsi103097.RequestEaCertificate;
import eu.fbk.aleph.its.aaca.utils.constants.ConfigConstants;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.groupsig.GroupJoinInteraction;
import org.certificateservices.custom.c2x.groupsig.authorization.InnerGroupRequest;
import org.certificateservices.custom.c2x.groupsig.authorization.InnerInteractionResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.groupsig.authorizationvalidation.GroupAuthorizationValidationRequest;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.jboss.logging.Logger;

import java.time.Duration;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Predicate;

public class GenGroupMember {

    private static final Logger LOGGER = Logger.getLogger(GenGroupMember.class);

    public static byte[] getGroupResponseEncoded(EtsiTs103097DataEncryptedUnicast groupJoinRequest) throws Exception {
        Map<HashedId8, Receiver> groupCARecipients =
                Setup.getMessagesCaGenerator().buildRecieverStore(
                        new Receiver[] {
                                new CertificateReciever(
                                        Setup.getAuthCredentialEncryptionKeys().getPrivate(),
                                        Setup.getAuthorizationCACertificate()
                                )
                        });

        if(Setup.getEnrollmentAuthorityCertificate() == null) {
            RequestEaCertificate requestEaCertificate = runWithRetry(
                    "enrollment authority certificate",
                    RequestEaCertificate::new,
                    eac -> eac.getEaCertificate() != null
            );

            EtsiTs103097Certificate rootAuthorityCertificate = Setup.getRootAuthorityCertificate();

            Setup.setEnrollmentAuthorityCertificate(requestEaCertificate.getEaCertificate());
            LOGGER.info("Enrollment authority certificate: " + Setup.getEnrollmentAuthorityCertificate());

            Setup.setTrustStore(Setup.getMessagesCaGenerator().buildCertStore(
                    new EtsiTs103097Certificate[]{
                            rootAuthorityCertificate
                    })
            );

            Setup.setEnrollmentCAChain(new EtsiTs103097Certificate[]{requestEaCertificate.getEaCertificate(), rootAuthorityCertificate});
            Setup.setEnrolCACertStore(Setup.getMessagesCaGenerator().buildCertStore(Setup.getEnrollmentCAChain()));

        }

        // To decrypt the message (not the inner eCSignature signed for EA CA).
        RequestVerifyResult<InnerGroupRequest> groupJoinRequestResult =
                Setup.getMessagesCaGenerator().decryptAndVerifyGroupJoinRequestMessage(
                        groupJoinRequest,
                        groupCARecipients // Receivers able to decrypt the message
                );

        InnerGroupRequest innerGroupRequest = groupJoinRequestResult.getValue();

        EcSignature ecSignature = groupJoinRequestResult.getValue().getEcSignature();

        GroupAuthorizationValidationRequest groupAuthorizationValidationRequestMessage =
                new GroupAuthorizationValidationRequest(
                        innerGroupRequest.getSharedGroupRequest(),
                        ecSignature
                );

        EncryptResult authorizationValidationRequestMessageResult =
                Setup.getMessagesCaGenerator().genGroupAuthorizationValidationRequest(
                        new Time64(new Date()),
                        groupAuthorizationValidationRequestMessage,
                        Setup.getAuthorizationCAChain(),
                        Setup.getAuthCredentialSigningKeys().getPrivate(),
                        Setup.getEnrollmentAuthorityCertificate()
        );

        if (authorizationValidationRequestMessageResult == null) {
            throw new Exception("Failed to generate group auth verification message.");
        }

        EtsiTs103097DataEncryptedUnicast encGroupAuthorizationVerificationRequest =
                (EtsiTs103097DataEncryptedUnicast) authorizationValidationRequestMessageResult.getEncryptedData();

        /*

        try (Client client = ClientBuilder.newClient()) {

            EtsiTs103097DataEncryptedUnicast encAuthorizationValidation = null;

            Response authorizationValidationResponse = client.target(ConfigConstants.DEFAULT_EA_AUTH_VER)
                    .request(MediaType.TEXT_PLAIN)
                    .post(Entity.entity(encGroupAuthorizationVerificationRequest.getEncoded(), MediaType.TEXT_PLAIN));

            Map<HashedId8, Receiver> authValidationSharedKeyReceivers = Setup.getMessagesCaGenerator().buildRecieverStore(
                    new Receiver[] {
                            new PreSharedKeyReceiver(
                                    SymmAlgorithm.aes128Ccm,
                                    authorizationValidationRequestMessageResult.getSecretKey()
                            )
                    });

            if (authorizationValidationResponse.getStatus() == 200) {
                byte[] authorizationValidationMessageEncoded = authorizationValidationResponse.readEntity(byte[].class);

                if (authorizationValidationMessageEncoded == null || authorizationValidationMessageEncoded.length == 0) {
                    LOGGER.error("Response message data is null or empty");
                    throw new Exception("Response message data is null or empty");
                }

                encAuthorizationValidation =
                        new EtsiTs103097DataEncryptedUnicast(authorizationValidationMessageEncoded);

            } else{
                LOGGER.error("Could not retrieve authorization validation response. HTTP status: " + authorizationValidationResponse.getStatus());
                throw new Exception("Failed to verify authorization validation response");
            }
            try {
                VerifyResult<AuthorizationValidationResponse> authorizationValidationResponseVerifyResult =
                        Setup.getMessagesCaGenerator().decryptAndVerifyAuthorizationValidationResponseMessage(
                                encAuthorizationValidation,
                                Setup.getEnrolCACertStore(),
                                Setup.getTrustStore(),
                                authValidationSharedKeyReceivers
                        );
            } catch (Exception e) {
                LOGGER.error("Failed to verify authorization validation response: " + e.getMessage());
                throw new Exception("Failed to verify authorization validation response", e);
            }
        }

         */
        long moutPtr = Setup.getAaGroupIssuer().joinMgr(0, 0);

        InnerInteractionResponse innerInteractionResponse = getInnerInteractionResponse(moutPtr);

        EtsiTs103097DataEncryptedUnicast groupResponseMessage =
                Setup.getMessagesCaGenerator().genInteractionResponseMessage(
                        new Time64(new Date()),
                        innerInteractionResponse,
                        Setup.getAuthorizationCAChain(), // The AA certificate chain signing the message
                        Setup.getAuthCredentialSigningKeys().getPrivate(),
                        SymmAlgorithm.aes128Ccm, // Encryption algorithm used.
                        groupJoinRequestResult.getSecretKey()
                ); // The symmetric key generated in the request.

        return groupResponseMessage.getEncoded();
    }

    private static InnerInteractionResponse getInnerInteractionResponse(long moutPtr) throws Exception {
        GrpKey grpKey = Setup.getAaGroupIssuer().getGrpKey();

        // LOGGER.info("Got PS16 member secret key: " + java.util.Arrays.toString(innerGroupRequest.getMemberGroupKey().getData()));
        // TODO: groupId is set to 0
        return new InnerInteractionResponse(
                new byte[8],
                GroupJoinInteraction.MOUT1,
                Setup.getAaGroupIssuer().messageToBase64(moutPtr),
                grpKey.export(),
                AuthorizationResponseCode.ok
        );
    }

    private static <T> T runWithRetry(String operationName, Callable<T> supplier, Predicate<T> successCondition) throws Exception {
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

}
