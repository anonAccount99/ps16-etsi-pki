package eu.fbk.aleph.its.aaca.api;

import eu.fbk.aleph.its.aaca.services.groupsig.GenInteraction;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.jboss.logging.Logger;

@Path("/group-interaction")
public class GroupInteraction {
    private static final Logger LOGGER = Logger.getLogger(GroupInteraction.class);

    @POST
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public Response mout(byte[] request) {
        try {
            EtsiTs103097DataEncryptedUnicast interactionRequest = new EtsiTs103097DataEncryptedUnicast(request);
            LOGGER.error("InnerInteractionResponse request received and deserialized: " + interactionRequest);
            byte[] interactionResponseEncoded = GenInteraction.getInteractionResponse(interactionRequest);
            return Response.ok(interactionResponseEncoded).build();
        } catch (Exception e) {
            LOGGER.error("Error generating interactionRequest response: " + e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Error generating interactionRequest response: " + e.getMessage())
                    .build();
        }
    }
}
