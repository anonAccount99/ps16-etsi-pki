package org.certificateservices.custom.c2x.groupsig.authorization;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.*;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode;
import org.certificateservices.custom.c2x.groupsig.GroupJoinInteraction;
import org.certificateservices.custom.c2x.groupsig.Ps16GroupPublicKey;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class InnerInteractionResponse extends COERSequence {

    private static final long serialVersionUID = 1L;

    private static final int REQUESTHASH = 0;
    private static final int INNERINERACTION = 1;
    private static final int RESPONSECODE = 2;


    /* A HashedId8 is always 8 bytes long. */
    private static final int HASHED_ID8_LEN  = 8;


    /** Default constructor – used by the COER decoder. */
    public InnerInteractionResponse() throws IOException {
        super(true,3);
        init();
    }

    public InnerInteractionResponse(
            byte[] requestHash,
            GroupJoinInteraction interaction,
            String moutBase64,
            String groupPublicKey,
            AuthorizationResponseCode responseCode
            ) throws IOException {
        this();

        set(REQUESTHASH, new COEROctetStream(requestHash, HASHED_ID8_LEN, HASHED_ID8_LEN));
        set(INNERINERACTION, new InnerInteraction(interaction, moutBase64, groupPublicKey));
        set(RESPONSECODE, new COEREnumeration(responseCode));
    }

    private void init() throws IOException {
        addField(REQUESTHASH, false, new COEROctetStream(null, HASHED_ID8_LEN, HASHED_ID8_LEN), null);
        addField(INNERINERACTION, false, new InnerInteraction(), null);
        addField(RESPONSECODE, false, new COEREnumeration(AuthorizationResponseCode.class), null);
    }

    public byte[] getRequestHash() {
        return ((COEROctetStream) get(REQUESTHASH)).getData();
    }

    public InnerInteraction getInnerInteraction() {
        return (InnerInteraction) get(INNERINERACTION);
    }

    public AuthorizationResponseCode getResponseCode() {
        return (AuthorizationResponseCode) ((COEREnumeration) get(RESPONSECODE)).getValue();
    }

    public byte[] getEncoded() throws IOException{
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        encode(dos);
        return baos.toByteArray();
    }

    @Override
    public String toString() {
        return "InnerInteractionResponse [\n" +
                "  requestHash=" + new String(Hex.encode(getRequestHash())) + "\n" +
                "  innerInteraction=" + getInnerInteraction() + "\n" +
                "  responseCode=" + getResponseCode() + "\n" +
                "]";
    }
}
