package org.certificateservices.custom.c2x.groupsig.authorization;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

import java.io.*;

public class SharedGroupRequest extends COERSequence {
    private static final int OCTETSTRING_SIZE = 16;

    private static final long serialVersionUID = 1L;

    private static final int EAID = 0;
    private static final int CERTIFICATEFORMAT = 1;
    private static final int REQUESTEDSUBJECTATTRIBUTES = 2;

    /**
     * Constructor used when decoding
     */
    public SharedGroupRequest(){
        super(true,3);
        init();
    }

    /**
     * Constructor used when encoding
     */
    public SharedGroupRequest(
            HashedId8 eaId,
            CertificateFormat certificateFormat,
            CertificateSubjectAttributes requestedSubjectAttributes
    ) throws IOException {
        super(true,3);
        init();

        if(requestedSubjectAttributes != null && requestedSubjectAttributes.getCertIssuePermissions() != null){
            throw new IOException("Invalid requestedSubjectAttributes in SharedGroupRequest, certIssuePermissions cannot be set.");
        }

        set(EAID, eaId);
        set(CERTIFICATEFORMAT, certificateFormat);
        set(REQUESTEDSUBJECTATTRIBUTES, requestedSubjectAttributes);
    }

    /**
     * Constructor decoding a SharedGroupRequest from an encoded byte array.
     * @param encodedData byte array encoding of the ToBeSignedCertificate.
     * @throws IOException   if communication problems occurred during serialization.
     */
    public SharedGroupRequest(byte[] encodedData) throws IOException{
        super(true,3);
        init();

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encodedData));
        decode(dis);
    }

    /**
     *
     * @return eaId value
     */
    public HashedId8 getEaId(){
        return (HashedId8) get(EAID);
    }

    /**
     *
     * @return certificateFormat value
     */
    public CertificateFormat getCertificateFormat(){
        return (CertificateFormat) get(CERTIFICATEFORMAT);
    }

    /**
     *
     * @return requestedSubjectAttributes value
     */
    public CertificateSubjectAttributes getRequestedSubjectAttributes(){
        return (CertificateSubjectAttributes) get(REQUESTEDSUBJECTATTRIBUTES);
    }


    private void init(){
        addField(EAID, false, new HashedId8(), null);
        addField(CERTIFICATEFORMAT, false, new CertificateFormat(), null);
        addField(REQUESTEDSUBJECTATTRIBUTES, false, new CertificateSubjectAttributes(), null);
    }

    /**
     * Encodes the SharedGroupRequest as a byte array.
     *
     * @return return encoded version of the SharedGroupRequest as a byte[]
     * @throws IOException if encoding problems of the data occurred.
     */
    public byte[] getEncoded() throws IOException{
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        encode(dos);
        return baos.toByteArray();
    }


    @Override
    public String toString() {
        return
                "SharedGroupRequest [\n" +
                        "  eaId=" + getEaId().toString().replaceAll("HashedId8 ", "") + "\n" +
                        "  certificateFormat=" + getCertificateFormat() + "\n" +
                        "  requestedSubjectAttributes=" + getRequestedSubjectAttributes().toString().replaceAll("CertificateSubjectAttributes ","").replaceAll("\n","\n  ") + "\n" +
                        "]";
    }
}
