package org.certificateservices.custom.c2x.groupsig.cert;

import com.ibm.jgroupsig.GS;
import com.ibm.jgroupsig.GrpKey;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

import java.io.IOException;
import java.util.Arrays;

public class AACert extends EtsiTs103097Certificate {
    private static final long serialVersionUID = 1L;
    GrpKey grpKey;

    /**
     * Default constructor.
     */
    public AACert() {
        super();
    }

    /**
     * Constructor with a certificate.
     *
     * @param certificate the certificate to set.
     */
    public AACert(
            byte[] certificate,
            GrpKey grpKey

    ) throws BadArgumentException, IOException {
        super(certificate);
        this.grpKey = grpKey;
    }

    public AACert(byte[] aaCertificateBytes) throws BadArgumentException, IOException {
        super(aaCertificateBytes);
        byte[] certBytes = this.getEncoded();
        int certLength = certBytes.length;

        if (aaCertificateBytes.length > certLength) {
            int grpKeyLength = aaCertificateBytes.length - certLength;
            byte[] grpKeyBytes = new byte[grpKeyLength];
            System.arraycopy(aaCertificateBytes, certLength, grpKeyBytes, 0, grpKeyLength);
            try {
                this.grpKey = new GrpKey(GS.PS16_CODE, Arrays.toString(grpKeyBytes));
            } catch (Exception e) {
                throw new IOException("Failed to load group key", e);
            }
        }
    }
    public GrpKey getGrpKey() {
        return grpKey;
    }
}
