package eu.fbk.its.ca.ea.api;

import eu.fbk.its.ca.ea.services.GenEnrollmentVerification;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.jboss.logging.Logger;

@Path("/enrollment-verification")
public class EnrollmentVerification {
    private static final Logger LOGGER = Logger.getLogger(EnrollmentVerification.class);
    @POST
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public Response generateEnrollmentVerification(byte[] request) {
        try {
            EtsiTs103097DataEncryptedUnicast enrollVerRequest = new EtsiTs103097DataEncryptedUnicast(request);
            LOGGER.info("Enrollment verification request received and deserialized: " + enrollVerRequest);
            byte[] enrollmentVerificationResponseEncoded = GenEnrollmentVerification.getEnrollmentVerification(enrollVerRequest);
            return Response.ok(enrollmentVerificationResponseEncoded).build();
        } catch (Exception e) {
            LOGGER.error("Error generating enrollment verification response: " + e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Error generating enrollment verification response: " + e.getMessage())
                    .build();
        }
    }
}
