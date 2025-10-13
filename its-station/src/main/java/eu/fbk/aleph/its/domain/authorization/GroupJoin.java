package eu.fbk.aleph.its.domain.authorization;

import com.ibm.jgroupsig.GS;
import com.ibm.jgroupsig.GrpKey;
import com.ibm.jgroupsig.MemKey;
import com.ibm.jgroupsig.PS16;
import eu.fbk.aleph.its.config.Setup;
import eu.fbk.aleph.its.domain.enrollment.EnrollmentCredentials;
import eu.fbk.aleph.its.utils.constant.ConfigConstants;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode;
import org.certificateservices.custom.c2x.groupsig.*;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.*;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.groupsig.authorization.InnerInteraction;
import org.certificateservices.custom.c2x.groupsig.authorization.InnerInteractionResponse;
import org.certificateservices.custom.c2x.groupsig.authorization.SharedGroupRequest;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.DENBasicService;

public class GroupJoin {
    private static final Logger LOGGER = Logger.getLogger(GroupJoin.class);
    private final SecureRandom secureRandom = new SecureRandom();
    private Map<HashedId8, Receiver> groupSharedKeyReceivers;
    private PS16 groupUser;
    private MemKey memKey;
    private boolean isGroupUserSet = false;
    private GrpKey issuerGroupKey = null;

    private static final int SWEDEN = 752;
    public GroupJoin() throws Exception {

        Ieee1609Dot2CryptoManager cryptoManager = Setup.getCryptoManager();
        ETSITS102941MessagesCaGenerator messagesCaGenerator = Setup.getMessagesCaGenerator();

        EnrollmentCredentials enrollmentCredentials = Setup.getEnrollmentCredentials();

        this.groupUser = new PS16();

        try (Client client = ClientBuilder.newClient()) {

            byte[] hmacKey = genHmacKey();
            SharedGroupRequest sharedGroupRequest = genSharedGoupRequest();

            LOGGER.error("hmacKey: " + Hex.toHexString(hmacKey));

            EncryptResult groupRequestMessageResult = messagesCaGenerator.genGroupJoinRequestMessage(
                    new Time64(new Date()), // generation Time
                    hmacKey,
                    sharedGroupRequest,
                    Setup.getEnrollmentCAChain(), // Certificate chain of enrolment credential to sign outer message to AA
                    enrollmentCredentials.getEnrollmentCredentialSigningKeys().getPrivate(), // Private key used to sign message.
                    Setup.getAuthorizationAuthorityCertificate(), // The AA certificate to encrypt outer message to.
                    enrollmentCredentials.getEnrollmentCertificate(), // Encrypt inner ecSignature with given certificate, required if withPrivacy is true.
                    true // Encrypt the inner ecSignature message sent to EA
            );

            if (groupRequestMessageResult == null) {
                throw new Exception("Failed to generate group request message.");
            }
            // send group request message to the AA (sending signed)
            EtsiTs103097DataEncryptedUnicast groupMoutMessage =
                    (EtsiTs103097DataEncryptedUnicast) groupRequestMessageResult.getEncryptedData();

            Response response1 = client.target(ConfigConstants.GROUP_AUTHORIZATION_URL)
                    .request(MediaType.TEXT_PLAIN)
                    .post(Entity.entity(groupMoutMessage.getEncoded(), MediaType.TEXT_PLAIN));

            InnerInteraction innerInteraction = handleInteractionResponse(
                    response1,
                    groupRequestMessageResult
            );

            EncryptResult interactionRequestMessageResult =
                    Setup.getMessagesCaGenerator().genInteractionRequestMessage(
                            new Time64(new Date()),
                            hmacKey,
                            innerInteraction,
                            Setup.getEnrollmentCAChain(), // Certificate chain of enrolment credential to sign outer message to AA
                            enrollmentCredentials.getEnrollmentCredentialSigningKeys().getPrivate(), // Private key used to sign message.
                            Setup.getAuthorizationAuthorityCertificate(), // The AA certificate to encrypt outer message to.
                            enrollmentCredentials.getEnrollmentCertificate(), // Encrypt inner ecSignature with given certificate, required if withPrivacy is true.
                            true // Encrypt the inner ecSignature message sent to EA
                    );

            LOGGER.error("Sending to AA: " + groupMoutMessage.toString());

            EtsiTs103097DataEncryptedUnicast interactionRequestMessage =
                    (EtsiTs103097DataEncryptedUnicast) interactionRequestMessageResult.getEncryptedData();

            Response response2 = client.target(ConfigConstants.GROUP_INTERACTION_URL)
                    .request(MediaType.TEXT_PLAIN)
                    .post(Entity.entity(interactionRequestMessage.getEncoded(), MediaType.TEXT_PLAIN));

            InnerInteraction innerInteractionResponse4 = handleInteractionResponse(
                    response2,
                    interactionRequestMessageResult
            );
            LOGGER.error("Group Join completed successfully. Mout4: " + innerInteractionResponse4.getMoutBase64());
        }
    }

    private InnerInteraction handleInteractionResponse(Response response, EncryptResult interactionMessageResult) throws Exception {
        long successiveMoutPtr = 0;
        GroupJoinInteraction successiveMoutInteraction = null;
        String exportedIssuerGroupKey = null;
        String successiveMoutPtrBase64 = "";
        if (response.getStatus() == 200) {
            byte[] interactionResponseMessageEncoded = response.readEntity(byte[].class);

            LOGGER.info("Received response data length: " + (interactionResponseMessageEncoded != null ? interactionResponseMessageEncoded.length : "null"));

            if (interactionResponseMessageEncoded == null || interactionResponseMessageEncoded.length == 0) {
                LOGGER.error("Response message data is null or empty");
                throw new Exception("Response message data is null or empty");
            }

            EtsiTs103097DataEncryptedUnicast interactionResponse =
                    new EtsiTs103097DataEncryptedUnicast(interactionResponseMessageEncoded);

            LOGGER.info("==============================================================");
            LOGGER.info("Successfully created EtsiTs103097DataEncryptedUnicast from response");
            LOGGER.info("Received interaction response from AA: " + interactionResponse);

            // Verify we have the secret key for decryption
            if (interactionMessageResult == null) {
                LOGGER.error("interactionMessageResult is null - cannot get secret key for decryption");
                throw new Exception("interactionMessageResult is null");
            }

            if (interactionMessageResult.getSecretKey() == null) {
                LOGGER.error("Secret key is null in interactionMessageResult");
                throw new Exception("Secret key is null - cannot decrypt response");
            }

            LOGGER.info("Secret key available for decryption");

            this.groupSharedKeyReceivers =
                    Setup.getMessagesCaGenerator().buildRecieverStore(
                            new Receiver[]{
                                    new PreSharedKeyReceiver(
                                            SymmAlgorithm.aes128Ccm,
                                            interactionMessageResult.getSecretKey()
                                    )
                            });

            LOGGER.info("Built receiver store with " + groupSharedKeyReceivers.size() + " receivers");

            CertStore authCACertStore = Setup.getMessagesCaGenerator().buildCertStore(Setup.getAuthorizationCAChain());
            LOGGER.info("Built certificate store");

            try {
                LOGGER.info("Starting decryption and verification process...");
                VerifyResult<InnerInteractionResponse> interactionResult =
                        Setup.getMessagesCaGenerator().decryptAndVerifyInteractionResponseMessage(
                                interactionResponse,
                                authCACertStore, // certificate store containing certificates for auth cert.
                                Setup.getTrustStore(),
                                groupSharedKeyReceivers
                        );

                LOGGER.info("Decryption and verification completed");

                // Add comprehensive null checking for the verification result
                if (interactionResult == null) {
                    LOGGER.error("decryptAndVerifyInteractionResponseMessage returned null");
                    throw new Exception("Failed to decrypt and verify interaction response message - result is null");
                }

                LOGGER.info("VerifyResult is not null, checking value...");

                InnerInteractionResponse receivedInnerInteractionResponse = interactionResult.getValue();

                // Add null checking for the inner interaction response
                if (receivedInnerInteractionResponse == null) {
                    LOGGER.error("Failed to extract InnerInteractionResponse from verify result - value is null");
                    throw new Exception("Failed to extract InnerInteractionResponse from verify result");
                }

                LOGGER.info("Successfully extracted InnerInteractionResponse");

                exportedIssuerGroupKey = receivedInnerInteractionResponse.getInnerInteraction().getGroupPublicKey();
                LOGGER.info("Received Group Public Key: " + exportedIssuerGroupKey);

                if (! this.isGroupUserSet){
                    this.issuerGroupKey = new GrpKey(GS.PS16_CODE, exportedIssuerGroupKey);
                    this.groupUser.setGrpKey(issuerGroupKey);
                    this.memKey = new MemKey(GS.PS16_CODE);
                    this.isGroupUserSet = true;
                }

                GroupJoinInteraction interaction = (GroupJoinInteraction) receivedInnerInteractionResponse.getInnerInteraction().getInteraction();
                String currentMoutBase64 = receivedInnerInteractionResponse.getInnerInteraction().getMoutBase64();
                long currentMoutPtr = this.groupUser.messageFromBase64(currentMoutBase64);

                LOGGER.error("Current InnerInteractionResponse Pointer: " + currentMoutPtr);

                LOGGER.info("Set user GrpKey: " + this.groupUser.getGrpKey().export());

                switch (interaction) {
                    case MOUT1:
                        LOGGER.info("Received MOUT1 interaction.");
                        successiveMoutPtr = this.groupUser.joinMem(this.memKey, 1, currentMoutPtr);
                        successiveMoutInteraction = GroupJoinInteraction.MOUT2;
                        exportedIssuerGroupKey = receivedInnerInteractionResponse.getInnerInteraction().getGroupPublicKey();
                        successiveMoutPtrBase64 = this.groupUser.messageToBase64(successiveMoutPtr);
                        break;
                    case MOUT3:
                        LOGGER.info("Received MOUT3 interaction.");
                        successiveMoutPtr = this.groupUser.joinMem(this.memKey, 3, currentMoutPtr);
                        successiveMoutInteraction = GroupJoinInteraction.MOUT4;
                        exportedIssuerGroupKey = receivedInnerInteractionResponse.getInnerInteraction().getGroupPublicKey();
                        break;
                    default:
                        LOGGER.error("GroupJoinInteraction: " + interaction);
                        throw new Exception("Unsupported GroupJoinInteraction: " + interaction);
                }
            } catch (Exception e) {
                LOGGER.error("Exception during decryption/verification: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                LOGGER.error("Stack trace: ", e);
                throw e;
            }
        } else {
            String errorResponse = response.readEntity(String.class);
            LOGGER.error("Failed to retrieve Group Membership. Status: " + response.getStatus());
            LOGGER.error("Error response: " + errorResponse);
            throw new Exception("Failed to retrieve Group Membership. Status: " + response.getStatus() + ", Error: " + errorResponse);
        }
        LOGGER.info("Successive InnerInteractionResponse Pointer: " + successiveMoutPtr);
        return new InnerInteraction(
                successiveMoutInteraction,
                successiveMoutPtrBase64,
                exportedIssuerGroupKey
        );
    }

    private SharedGroupRequest genSharedGoupRequest() throws Exception {
        HashedId8 eaId = new HashedId8(Setup.getCryptoManager().digest(Setup.getEnrollmentAuthorityCertificate().getEncoded(), HashAlgorithm.sha256));
        // byte[] keyTag = genKeyTag(hmacKey,publicKeys.getVerificationKey(),publicKeys.getEncryptionKey());
        PsidSsp appPermDenm = new PsidSsp(DENBasicService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.bitmapSsp, new BitmapSsp(new byte[]{0x01, 0x5F, 0x07, 0x25})));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermDenm};

        CertificateSubjectAttributes certificateSubjectAttributes =
                genCertificateSubjectAttributes(
                        "obu.example.com", // Hostname
                        new ValidityPeriod( // Define requested validity period
                                new SimpleDateFormat("yyyyMMdd HH:mm:ss").parse("20181202 12:12:21"), // Start time
                                Duration.DurationChoices.years, 25 // Duration
                        ),
                        GeographicRegion.generateRegionForCountrys(List.of(SWEDEN)),
                        new SubjectAssurance(2, 0),
                        appPermissions,
                        null
                );

        return new SharedGroupRequest(eaId, CertificateFormat.TS103097C131, certificateSubjectAttributes);
    }

    private CertificateSubjectAttributes genCertificateSubjectAttributes(
            String hostname,
            ValidityPeriod validityPeriod,
            GeographicRegion region,
            SubjectAssurance assuranceLevel,
            PsidSsp[] appPermissions,
            PsidGroupPermissions[] certIssuePermissions
    ) throws Exception {

        return new CertificateSubjectAttributes(
                (hostname != null ? new CertificateId(new Hostname(hostname)): new CertificateId()),
                validityPeriod,
                region,
                assuranceLevel,
                new SequenceOfPsidSsp(appPermissions),
                (certIssuePermissions != null ?
                        new SequenceOfPsidGroupPermissions(certIssuePermissions) : null)
        );
    }

    private byte[] genKeyTag(byte[] hmacKey, PublicVerificationKey verificationKey, PublicEncryptionKey encryptionKey) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream daos = new DataOutputStream(baos);
        daos.write(hmacKey);
        verificationKey.encode(daos);
        if(encryptionKey != null){
            encryptionKey.encode(daos);
        }
        daos.close();
        byte[] data = baos.toByteArray();
        Digest digest = new SHA256Digest();
        HMac hMac = new HMac(digest);
        hMac.update(data,0,data.length);

        byte[] macData = new byte[hMac.getMacSize()];
        hMac.doFinal(data,0);

        return Arrays.copyOf(macData,16);
    }

    private byte[] genHmacKey(){
        byte[] hmacKey = new byte[32];
        secureRandom.nextBytes(hmacKey);
        return hmacKey;
    }

    public MemKey getMemKey() {
        return memKey;
    }

    public PS16 getGroupUser() {
        return groupUser;
    }

}
