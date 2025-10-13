package org.certificateservices.custom.c2x.groupsig;

import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import java.io.IOException;

/**
 *  Ps16MemberSecretKey ::= OCTET STRING (SIZE(64..512))
 * <p>
 *  Implements COEREncodable by delegating all heavy lifting
 *  to an internal COEROctetStream helper → “implement-don’t-extend”.
 */
public final class Ps16MemberSecretKey extends COEROctetStream {

    public static final int MIN_LEN = 16;
    public static final int MAX_LEN = 512;

    /**  Decoder constructor – COER runtime will invoke this via reflection. */
    public Ps16MemberSecretKey() throws IOException {
        super(null, MIN_LEN, MAX_LEN);
    }

    /**  Encoder-side convenience constructor. */
    public Ps16MemberSecretKey(byte[] rawKey) throws IOException {
        super(rawKey, MIN_LEN, MAX_LEN);
    }
}