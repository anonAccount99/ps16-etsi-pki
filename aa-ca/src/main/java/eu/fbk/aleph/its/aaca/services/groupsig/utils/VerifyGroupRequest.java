package eu.fbk.aleph.its.aaca.services.groupsig.utils;

import eu.fbk.aleph.its.aaca.config.Setup;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageProcessingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.groupsig.authorization.InnerGroupRequest;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

public class VerifyGroupRequest {
    static Map<HashedId8, Receiver> groupCARecipients;
    static {
        try {
            groupCARecipients = Setup.getMessagesCaGenerator().buildRecieverStore(
                    new Receiver[] {
                            new CertificateReciever(
                                    Setup.getAuthCredentialEncryptionKeys().getPrivate(),
                                    Setup.getAuthorizationCACertificate()
                            )
                    });
        } catch (BadArgumentException | GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static RequestVerifyResult<InnerGroupRequest> verifyGroupRequest(
            EtsiTs103097DataEncryptedUnicast groupJoinRequest
    ) throws BadArgumentException,
            MessageParsingException,
            SignatureVerificationException,
            DecryptionFailedException,
            MessageProcessingException
    {
        return Setup.getMessagesCaGenerator().decryptAndVerifyGroupJoinRequestMessage(
                groupJoinRequest,
                groupCARecipients // Receivers able to decrypt the message
        );
    }

}

