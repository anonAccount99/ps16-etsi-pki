/************************************************************************
 *                                                                       *
 *  Certificate Service -  Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.groupsig.authorization;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Class representing InnerGroupRequest defined in ETSI TS 102 941 Authorization Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class InnerGroupRequest extends COERSequence {

	private static final int OCTETSTRING_SIZE = 32;

	private static final long serialVersionUID = 1L;

	private static final int HMACKEY = 0;
	private static final int SHAREDGROUPREQUEST = 1;
	private static final int ECSIGNATURE = 2;

	/**
	 * Constructor used when decoding
	 */
	public InnerGroupRequest() throws IOException {
		super(true,3);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public InnerGroupRequest(
			byte[] hmacKey,
			SharedGroupRequest sharedGroupRequest,
			EcSignature ecSignature
	) throws IOException {
		super(true,3);
		init();
		set(HMACKEY, new COEROctetStream(hmacKey, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
		set(SHAREDGROUPREQUEST, sharedGroupRequest);
		set(ECSIGNATURE, ecSignature);
	}


	private void init(){
		addField(HMACKEY, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
		addField(SHAREDGROUPREQUEST, false, new SharedGroupRequest(), null);
		addField(ECSIGNATURE, false, new EcSignature(), null);
	}

	public String getType() {
		return "InnerGroupRequest";
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

    @Override
    public String toString() {
        return
                "InnerGroupRequest [\n" +
                        "  hmacKey=" + new String(Hex.encode(getHmacKey())) + "\n" +
                        "  sharedGroupRequest=" + getSharedGroupRequest().toString().replaceAll("sharedGroupRequest ","").replaceAll("\n","\n  ")  + "\n" +
                        "  ecSignature=" + getEcSignature().toString().replaceAll("EcSignature ","").replaceAll("\n","\n  ") + "\n" +
						"]";
    }

}
