package org.certificateservices.custom.c2x.groupsig.authorization;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.asn1.coer.COERUTF8String;
import org.certificateservices.custom.c2x.groupsig.GroupJoinInteraction;
import org.certificateservices.custom.c2x.groupsig.Ps16GroupPublicKey;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class InnerInteraction extends COERSequence {

    private static final long serialVersionUID = 1L;

    private static final int INTERACTION   = 0;
    private static final int MOUT_BASE64 = 1;
    private static final int GROUP_PUBLIC_KEY = 2;

    /* A HashedId8 is always 8 bytes long. */
    private static final int HASHED_ID8_LEN  = 8;


    /** Default constructor – used by the COER decoder. */
    public InnerInteraction() throws IOException {
        super(true,3);
        init();
    }

    public InnerInteraction(
            GroupJoinInteraction interaction,
            String moutBase64,
            String groupPublicKey
    ) throws IOException {
        this();
        set(INTERACTION, new COEREnumeration(interaction));
        set(MOUT_BASE64, new COERUTF8String(moutBase64));
        set(GROUP_PUBLIC_KEY, new Ps16GroupPublicKey(groupPublicKey));
    }

    private void init() throws IOException {
        addField(INTERACTION, false, new COEREnumeration(GroupJoinInteraction.class), null);
        addField(MOUT_BASE64, false, new COERUTF8String(), null);
        addField(GROUP_PUBLIC_KEY, false, new Ps16GroupPublicKey(), null);
    }


    public GroupJoinInteraction getInteraction() {
        return (GroupJoinInteraction) ((COEREnumeration) get(INTERACTION)).getValue();
    }

    public String getMoutBase64() {
        return ((COERUTF8String) get(MOUT_BASE64)).getUTF8String();
    }

    public String getGroupPublicKey() {
        return ((Ps16GroupPublicKey) get(GROUP_PUBLIC_KEY)).getUTF8String();
    }

    public byte[] getEncoded() throws IOException{
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        encode(dos);
        return baos.toByteArray();
    }

    @Override
    public String toString() {
        return "InnerInteraction [\n" +
                "  interaction=" + getInteraction() + "\n" +
                "  moutBase64=" + getMoutBase64() + "\n" +
                "  groupPublicKey=" + getGroupPublicKey() + "\n" +
                "]";
    }
}
