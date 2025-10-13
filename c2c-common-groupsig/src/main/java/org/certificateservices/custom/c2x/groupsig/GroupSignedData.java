package org.certificateservices.custom.c2x.groupsig;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.ToBeSignedData;

import java.io.IOException;

public class GroupSignedData extends COERSequence {

    private static final long serialVersionUID = 1L;

    private static final int HASHID = 0;
    private static final int TBSDATA = 1;
    private static final int SIGNATURE = 2;

    /**
     * Constructor used when decoding
     */
    public GroupSignedData(){
        super(false,3);
        init();
    }

    /**
     * Constructor used when encoding
     */
    public GroupSignedData(
            HashAlgorithm hashAlgorithm,
            ToBeSignedData tbsData,
            Signature signature
    ) throws IOException {
        super(false,3);
        init();
        if(hashAlgorithm == null){
            throw new IOException("Error argument hashAlgorithm cannot be null for SignedData.");
        }
        set(HASHID, new COEREnumeration(hashAlgorithm));
        set(TBSDATA, tbsData);
        set(SIGNATURE, signature);
    }

    /**
     *
     * @return hashAlgorithm
     */
    public HashAlgorithm getHashAlgorithm(){
        return (HashAlgorithm) ((COEREnumeration) get(HASHID)).getValue();
    }

    /**
     *
     * @return tbsData
     */
    public ToBeSignedData getTbsData(){
        return (ToBeSignedData) get(TBSDATA);
    }

    /**
     *
     * @return signature
     */
    public Signature getSignature(){
        return (Signature) get(SIGNATURE);
    }

    private void init(){
        addField(HASHID, false, new COEREnumeration(HashAlgorithm.class), null);
        addField(TBSDATA, false, new ToBeSignedData(), null);
        addField(SIGNATURE, false, new Signature(), null);
    }

    @Override
    public String toString() {
        return "SignedData [\n"+
                "  hashAlgorithm=" + getHashAlgorithm() +  ",\n"+
                "  tbsData=" + getTbsData().toString().replace("ToBeSignedData ", "").replaceAll("\n", "\n  ") +  ",\n" +
                "  signature=" + getSignature().toString().replace("Signature ", "") +  "\n" +
                "]";
    }
}
