package eu.fbk.aleph.its.aaca.api;

import eu.fbk.aleph.its.aaca.services.groupsig.GenGroupMember;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.jboss.logging.Logger;

@Path("/group-membership")
public class GroupMembership {

    private static final Logger LOGGER = Logger.getLogger(GroupMembership.class);

    @POST
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public Response groupMembership(byte[] request) {
        try {
            EtsiTs103097DataEncryptedUnicast groupJoinRequest = new EtsiTs103097DataEncryptedUnicast(request);
            LOGGER.info("Authorization request received and deserialized: " + groupJoinRequest);
            byte[] groupResponseEncoded = GenGroupMember.getGroupResponseEncoded(groupJoinRequest);
            return Response.ok(groupResponseEncoded).build();
        } catch (Exception e) {
            LOGGER.error("Error generating authorization response: " + e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Error generating authorization response: " + e.getMessage())
                    .build();
        }
    }
}
