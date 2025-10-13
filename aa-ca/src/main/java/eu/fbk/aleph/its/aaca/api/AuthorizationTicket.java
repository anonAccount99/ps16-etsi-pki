package eu.fbk.aleph.its.aaca.api;

import eu.fbk.aleph.its.aaca.services.etsi103097.GenAuthorizationTicket;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.jboss.logging.Logger;

/**
 * Defines a JAX-RS resource endpoint for generating Authorization Tickets (ATs).
 * This class handles requests to create new AT certificates based on provided details.
 */
@Path("/authorization-ticket")
public class AuthorizationTicket {
    /**
     * Logger instance for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AuthorizationTicket.class);

    /**
     * Handles HTTP POST requests to the /authorization-ticket path.
     * Expects a JSON request body containing details for the new Authorization Ticket,
     * deserialized into a RequestCertificateDto object.
     * Calls a service method to generate the AT based on the request data.
     * Returns the generated Authorization Ticket certificate encoded as a hexadecimal string
     * in the response body with a plain text media type.
     * Handles potential exceptions during generation and returns an HTTP 400 Bad Request
     * response with an error message if an error occurs.
     *
     * @param request A RequestCertificateDto object containing the parameters for the AT.
     * @return A JAX-RS Response object containing either the hex-encoded AT (200 OK)
     * or an error message (400 Bad Request).
     */
    @POST
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public Response authorizationTicket(byte[] request) {
        try {
            EtsiTs103097DataEncryptedUnicast authRequest = new EtsiTs103097DataEncryptedUnicast(request);
            LOGGER.error("Authorization request received and deserialized: " + authRequest);
            byte[] authResponseEncoded = GenAuthorizationTicket.getAuthorizationTicket(authRequest);
            return Response.ok(authResponseEncoded).build();
        } catch (Exception e) {
            LOGGER.error("Error generating authorization response: " + e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Error generating authorization response: " + e.getMessage())
                    .build();
        }
    }
}

