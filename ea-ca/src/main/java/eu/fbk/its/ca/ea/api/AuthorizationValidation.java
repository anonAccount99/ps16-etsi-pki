package eu.fbk.its.ca.ea.api;

import eu.fbk.its.ca.ea.utils.constants.ConfigConstants;
import eu.fbk.its.ca.ea.services.groupsig.GenAuthorizationValidation;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.jboss.logging.Logger;

@Path("/auth-validation")
public class AuthorizationValidation {
    private static final Logger LOGGER = Logger.getLogger(AuthorizationValidation.class);

    @POST
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public Response authorizationValidation(byte[] request) {
        try {
            EtsiTs103097DataEncryptedUnicast authValRequest = new EtsiTs103097DataEncryptedUnicast(request);
            LOGGER.error("Authorization validation request received and deserialized: " + authValRequest);
            byte[] authValResponseEncoded = GenAuthorizationValidation.getAuthorizationValidation(authValRequest);
            return Response.ok(authValResponseEncoded).build();
        } catch (Exception e) {
            LOGGER.error("Error generating authorization response: " + e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Error generating authorization response: " + e.getMessage())
                    .build();
        }
    }
}
