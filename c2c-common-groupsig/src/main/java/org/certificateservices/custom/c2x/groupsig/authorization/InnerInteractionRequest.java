package org.certificateservices.custom.c2x.groupsig.authorization;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature;

import java.io.IOException;

public class InnerInteractionRequest extends COERSequence {
    private static final int OCTETSTRING_SIZE = 32;

    private static final long serialVersionUID = 1L;

    private static final int HMACKEY = 0;
    private static final int INNERINERACTION = 1;
    private static final int ECSIGNATURE = 2;

    /**
     * Constructor used when decoding
     */
    public InnerInteractionRequest() throws IOException {
        super(true,3);
        init();
    }

    /**
     * Constructor used when encoding
     */
    public InnerInteractionRequest(
            byte[] hmacKey,
            InnerInteraction innerInteraction,
            EcSignature ecSignature
    ) throws IOException {
        super(true,4);
        init();
        set(HMACKEY, new COEROctetStream(hmacKey, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
        set(INNERINERACTION, innerInteraction);
        set(ECSIGNATURE, ecSignature);
    }

    /**
     *
     * @return the 32 byte hmacKey value
     */
    public byte[] getHmacKey(){
        return ((COEROctetStream) get(HMACKEY)).getData();
    }

    /**
     *
     * @return sharedAtRequest value
     */
    public InnerInteraction getInnerInteraction(){
        return (InnerInteraction) get(INNERINERACTION);
    }

    /**
     *
     * @return ecSignature value
     */
    public EcSignature getEcSignature(){
        return (EcSignature) get(ECSIGNATURE);
    }

    private void init() throws IOException {
        addField(HMACKEY, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
        addField(INNERINERACTION, false, new InnerInteraction(), null);
        addField(ECSIGNATURE, false, new EcSignature(), null);
    }

    @Override
    public String toString() {
        return
                "InnerInteractionRequest [\n" +
                        "  hmacKey=" + new String(Hex.encode(getHmacKey())) + "\n" +
                        "  innerInteraction=" + getInnerInteraction().toString().replaceAll("Mout ","").replaceAll("\n","\n  ") + "\n" +
                        "  ecSignature=" + getEcSignature().toString().replaceAll("EcSignature ","").replaceAll("\n","\n  ") + "\n" +
                        "]";
    }
}
