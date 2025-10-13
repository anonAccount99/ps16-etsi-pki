package eu.fbk.aleph.its.domain.denm.transmission.etsi103097;

import eu.fbk.aleph.its.config.Setup;
import eu.fbk.aleph.its.domain.authorization.AuthorizationCredentials;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Date;


public class DenmGenerator {
    private final AuthorizationCredentials authorizationCredentials;
    private final byte[] payload;

    public DenmGenerator(
            AuthorizationCredentials authorizationCredentials,
            byte[] payload
    ){
        this.authorizationCredentials = authorizationCredentials;
        this.payload = payload;
    }


    public EtsiTs103097DataSigned genDENMessage() throws IOException, BadArgumentException, SignatureException {
        ETSISecuredDataGenerator securedMessageGenerator = Setup.getSecuredMessageGenerator();
        return securedMessageGenerator.genDENMessage(
                new Time64(new Date()), // generationTime
                new ThreeDLocation(1,2,3), // generationLocation
                payload, // inner opaque DEN message data
                authorizationCredentials.getAuthorizationTicket(), // signerCertificate
                authorizationCredentials.getAuthTicketSignKeys().getPrivate()); // signerPrivateKey
    }
}
