package eu.fbk.aleph.its.aaca.services.groupsig;

import com.ibm.jgroupsig.GS;
import com.ibm.jgroupsig.GrpKey;
import com.ibm.jgroupsig.MemKey;
import com.ibm.jgroupsig.PS16;
import eu.fbk.aleph.its.aaca.config.Setup;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.groupsig.GroupJoinInteraction;
import org.certificateservices.custom.c2x.groupsig.authorization.InnerInteractionRequest;
import org.certificateservices.custom.c2x.groupsig.authorization.InnerInteractionResponse;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.jboss.logging.Logger;

import java.util.Date;
import java.util.Objects;

public class GenInteraction {

    private static final Logger LOGGER = Logger.getLogger(GenInteraction.class);

    public static byte[] getInteractionResponse(EtsiTs103097DataEncryptedUnicast nextMoutRequest) throws Exception {

        LOGGER.error("Received MOUT request: " + nextMoutRequest);
        // To decrypt the message and verify the external POP signature (not the inner eCSignature signed for EA CA).
        RequestVerifyResult<InnerInteractionRequest> interactionRequestResult =
                Setup.getMessagesCaGenerator().decryptAndVerifyInteractionRequestMessage(
                        nextMoutRequest,
                        //true, // Expect InteractionRequestPOP content
                        Setup.getMessagesCaGenerator().buildRecieverStore(
                                new Receiver[] {
                                        new CertificateReciever(
                                                Setup.getAuthCredentialEncryptionKeys().getPrivate(),
                                                Setup.getAuthorizationCACertificate()
                                        )
                                }
                        ) // Receivers able to decrypt the message
                );

        InnerInteractionRequest innerInteractionRequest = interactionRequestResult.getValue();

        GroupJoinInteraction interaction = innerInteractionRequest.getInnerInteraction().getInteraction();
        long successiveMoutPtr = 0;
        GroupJoinInteraction successiveMoutInteraction = null;
        String exportedGroupPublicKey = null;

        if (Objects.requireNonNull(interaction) == GroupJoinInteraction.MOUT2) {
            LOGGER.info("Received MOUT2 interaction.");
            long currentMoutPtr= Setup.getAaGroupIssuer().messageFromBase64(innerInteractionRequest.getInnerInteraction().getMoutBase64());
            LOGGER.info("innerInteractionRequest.getMout().getMoutBase64(): " + innerInteractionRequest.getInnerInteraction().getMoutBase64());
            LOGGER.info("currentMoutPtr: " + currentMoutPtr);
            testSign();
            successiveMoutPtr = Setup.getAaGroupIssuer().joinMgr(
                    2,
                    currentMoutPtr
                    );
            successiveMoutInteraction = GroupJoinInteraction.MOUT3;
            exportedGroupPublicKey = Setup.getAaGroupIssuer().getGrpKey().export();
        } else {
            LOGGER.error("GroupJoinInteraction: " + interaction);
            throw new Exception("Unsupported GroupJoinInteraction: " + interaction);
        }

        // LOGGER.info("Got PS16 member secret key: " + java.util.Arrays.toString(innerGroupRequest.getMemberGroupKey().getData()));

        // TODO: groupId is set to 0
        InnerInteractionResponse innerInteractionResponse = new InnerInteractionResponse(
                new byte[8],
                successiveMoutInteraction,
                Setup.getAaGroupIssuer().messageToBase64(successiveMoutPtr),
                exportedGroupPublicKey,
                AuthorizationResponseCode.ok
        );

        LOGGER.info("Generated innerInteractionResponse: " + innerInteractionResponse);

        EtsiTs103097DataEncryptedUnicast groupResponseMessage =
                Setup.getMessagesCaGenerator().genInteractionResponseMessage(
                        new Time64(new Date()),
                        innerInteractionResponse,
                        Setup.getAuthorizationCAChain(), // The AA certificate chain signing the message
                        Setup.getAuthCredentialSigningKeys().getPrivate(),
                        SymmAlgorithm.aes128Ccm, // Encryption algorithm used.
                        interactionRequestResult.getSecretKey() // The symmetric key generated in the request.
                ); // The symmetric key generated in the request.

        return groupResponseMessage.getEncoded();
    }

    private static void testSign() throws Exception {
        PS16 groupUser = new PS16();
        groupUser.setGrpKey(
                new GrpKey(
                        GS.PS16_CODE,
                        Setup.getAaGroupIssuer().getGrpKey().export()
                )
        );
        String message = "010203040506";
        MemKey memKey = new MemKey(GS.PS16_CODE);
        long moutPtr = Setup.getAaGroupIssuer().joinMgr(0, 0);
        moutPtr = groupUser.joinMem(memKey, 1, groupUser.messageFromBase64(Setup.getAaGroupIssuer().messageToBase64(moutPtr)));
        moutPtr = Setup.getAaGroupIssuer().joinMgr(2, Setup.getAaGroupIssuer().messageFromBase64(groupUser.messageToBase64(moutPtr)));
        groupUser.joinMem(memKey, 3, groupUser.messageFromBase64(Setup.getAaGroupIssuer().messageToBase64(moutPtr)));
        LOGGER.error("Test string signature exported: " + groupUser.sign(message, memKey).export());
    }

}
