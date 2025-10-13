package org.certificateservices.custom.c2x.groupsig;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.asn1.coer.COERUTF8String;

import java.io.IOException;

public class Bls12381PS16Signature extends COERSequence {

    private static final int OCTETSTRING_SIZE = 32;

    private static final long serialVersionUID = 1L;

    private static final int GROUPSIG = 0;
    private static final int GROUPPUBLICKEY = 1;

    /**
     * Constructor used when decoding
     */
    public Bls12381PS16Signature(){
        super(false,2);
        init();
    }

    /**
     * Constructor used when encoding
     */
    public Bls12381PS16Signature(String base64GroupSig, String exportedGroupPublicKey) throws IOException {
        super(false,2);
        init();
        if(base64GroupSig == null){
            throw new IOException("Error base64GroupSig value cannot be null in Bls12381PS16Signature");
        }
        set(GROUPSIG, new COERUTF8String(base64GroupSig));
        set(GROUPPUBLICKEY, new COERUTF8String(exportedGroupPublicKey));
    }


    private void init(){
        addField(GROUPSIG, false, new COERUTF8String(), null);
        addField(GROUPPUBLICKEY, false, new COERUTF8String(), null);
    }

    /**
     *
     * @return base64 encoded group signature
     */
    public String getGroupSig() {
        return ((COERUTF8String) get(GROUPSIG)).getUTF8String();
    }

    /**
     *
     * @return base64 encoded group public key
     */
    public String getGroupPublicKey() {
        return ((COERUTF8String) get(GROUPPUBLICKEY)).getUTF8String();
    }

}
