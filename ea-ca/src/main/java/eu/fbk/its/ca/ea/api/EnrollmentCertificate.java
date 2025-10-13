package eu.fbk.its.ca.ea.api;

import eu.fbk.its.ca.ea.services.GenEnrollmentCertificate;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.jboss.logging.Logger;

/**
 * Defines a JAX-RS resource endpoint for handling Enrollment Certificate (EC) requests.
 * This class receives encrypted EC requests, processes them, and returns encrypted responses
 * containing the generated Enrollment Certificate.
 */
@Path("/enrollment-certificate")
public class EnrollmentCertificate {

    /**
     * Logger instance for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(EnrollmentCertificate.class);

    /**
     * Handles HTTP POST requests to the /enrollment-certificate path.
     * Expects the raw bytes of an encrypted enrollment request message in the request body,
     * declared with a media type of text/plain.
     * Deserializes the request, calls a service method to generate the enrollment response
     * (which includes the Enrollment Certificate), and returns the encoded response message
     * as raw bytes in the response body, also declared as text/plain.
     * Handles potential exceptions during processing and returns an HTTP 400 Bad Request
     * response with an error message if an error occurs.
     *
     * @param request A byte array containing the encoded EtsiTs103097DataEncryptedUnicast enrollment request.
     * @return A JAX-RS Response object containing either the encoded byte array of the enrollment response (200 OK)
     * or an error message (400 Bad Request).
     */
    @POST
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public Response generateEnrollmentCA(byte[] request) {
        try {
            EtsiTs103097DataEncryptedUnicast ecRequest = new EtsiTs103097DataEncryptedUnicast(request);
            LOGGER.info("Enrollment request received and deserialized: " + ecRequest);
            byte[] enrollmentResponseEncoded = GenEnrollmentCertificate.getEnrollCertificate(ecRequest);
            return Response.ok(enrollmentResponseEncoded).build();
        } catch (Exception e) {
            LOGGER.error("Error generating enrollment response: " + e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Error generating enrollment response: " + e.getMessage())
                    .build();
        }
    }
}

