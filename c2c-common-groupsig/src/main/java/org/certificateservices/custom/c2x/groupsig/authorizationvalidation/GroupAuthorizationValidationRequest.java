package org.certificateservices.custom.c2x.groupsig.authorizationvalidation;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature;
import org.certificateservices.custom.c2x.groupsig.authorization.SharedGroupRequest;

import java.io.IOException;

public class GroupAuthorizationValidationRequest extends COERSequence {

    private static final long serialVersionUID = 1L;

    private static final int SHAREDGROUPREQUEST = 0;
    private static final int ECSIGNATURE = 1;

    /**
     * Constructor used when decoding
     */
    public GroupAuthorizationValidationRequest(){
        super(true,2);
        init();
    }

    /**
     * Constructor used when encoding
     */
    public GroupAuthorizationValidationRequest(SharedGroupRequest sharedGroupRequest, EcSignature ecSignature) throws IOException {
        super(true,2);
        init();
        set(SHAREDGROUPREQUEST, sharedGroupRequest);
        set(ECSIGNATURE, ecSignature);
    }

    /**
     *
     * @return sharedAtRequest value
     */
    public SharedGroupRequest getSharedGroupRequest(){
        return (SharedGroupRequest) get(SHAREDGROUPREQUEST);
    }

    /**
     *
     * @return ecSignature value
     */
    public EcSignature getEcSignature(){
        return (EcSignature) get(ECSIGNATURE);
    }

    private void init(){
        addField(SHAREDGROUPREQUEST, false, new SharedGroupRequest(), null);
        addField(ECSIGNATURE, false, new EcSignature(), null);
    }

    @Override
    public String toString() {
        return
                "AuthorizationValidationRequest [\n" +
                        "  sharedGroupRequest=" + getSharedGroupRequest().toString().replaceAll("SharedGroupRequest ","").replaceAll("\n","\n  ")  + "\n" +
                        "  ecSignature=" + getEcSignature().toString().replaceAll("EcSignature ","").replaceAll("\n","\n  ") + "\n" +
                        "]";
    }

}
