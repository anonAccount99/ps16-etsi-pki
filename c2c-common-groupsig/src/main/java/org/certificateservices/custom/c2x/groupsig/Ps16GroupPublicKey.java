package org.certificateservices.custom.c2x.groupsig;

import org.certificateservices.custom.c2x.asn1.coer.COERUTF8String;

import java.io.IOException;

public class Ps16GroupPublicKey extends COERUTF8String {

    public Ps16GroupPublicKey() throws IOException {
        super("");
    }

    public Ps16GroupPublicKey(String stringKey) throws IOException {
        super(stringKey);
    }
}
