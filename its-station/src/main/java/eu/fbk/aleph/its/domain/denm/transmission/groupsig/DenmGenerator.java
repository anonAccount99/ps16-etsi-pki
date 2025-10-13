package eu.fbk.aleph.its.domain.denm.transmission.groupsig;

import com.ibm.jgroupsig.MemKey;
import com.ibm.jgroupsig.PS16;
import eu.fbk.aleph.its.config.Setup;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Date;


public class DenmGenerator {
    private final PS16 groupUser;
    private final MemKey memKey;
    private final byte[] payload;

    public DenmGenerator(
            PS16 groupUser,
            MemKey memKey,
            byte[] payload
    ){
        this.groupUser = groupUser;
        this.memKey = memKey;
        this.payload = payload;
    }

    public EtsiTs103097DataSigned genDENMessage() throws IOException, BadArgumentException, SignatureException {
        ETSISecuredDataGenerator securedMessageGenerator = Setup.getSecuredMessageGenerator();
        // AuthorizationCredentials authorizationCredentials = Setup.getAuthorizationCredentials();

        return securedMessageGenerator.genDENMessage(
                new Time64(new Date()), // generationTime
                new ThreeDLocation(1,2,3), // generationLocation
                payload, // inner opaque DEN message data
                groupUser,
                memKey
        );
    }
}
