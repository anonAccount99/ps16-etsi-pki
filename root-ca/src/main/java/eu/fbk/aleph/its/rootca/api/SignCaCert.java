package eu.fbk.aleph.its.rootca.api;


import eu.fbk.aleph.its.rootca.services.CertSig;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.dto.RequestCertificateDto;
import org.jboss.logging.Logger;

@Path("/certificate-sign")
public class SignCaCert {

    private static final Logger LOGGER = Logger.getLogger(SignCaCert.class);

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public Response generateEnrollmentCA(RequestCertificateDto request) {
        try {
            LOGGER.info("Received certificate sign request: " + request);

            // Call service to generate the certificate
            EtsiTs103097Certificate enrollmentCACertificate = CertSig.generateCA(
                    request.getId(),
                    request.getValidityPeriod(),
                    request.getRegion_code(),
                    request.getSubjectAssuranceLevel(),
                    request.getSubjectConfidenceLevel(),
                    request.getSigningPublicKey(),
                    request.getEncryptionPublicKey()
            );

            LOGGER.info("Enrollment CA certificate generated successfully.");
            // Return the generated certificate
            String hexEncodedCert = Hex.toHexString(enrollmentCACertificate.getEncoded());
            return Response.ok(hexEncodedCert).build();
        } catch (Exception e) {
            LOGGER.error("Error generating enrollment CA: " + e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Error generating enrollment CA: " + e.getMessage())
                    .build();
        }
    }
}
