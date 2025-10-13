package eu.fbk.its.ca.ea.api;

import eu.fbk.its.ca.ea.config.Setup;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;

import java.io.IOException;

/**
 * Defines a JAX-RS resource endpoint for retrieving the Enrollment Authority (EA) certificate.
 * This class exposes the EA's certificate via a RESTful API.
 */
@Path("/certificate")
public class EaCertificate {
    /**
     * Logger instance for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(EaCertificate.class);

    /**
     * Handles HTTP GET requests to the /certificate path.
     * Retrieves the pre-configured Enrollment Authority (EA) certificate
     * from the Setup class, gets its encoded byte representation, and returns it.
     * The response body will contain the raw bytes of the certificate,
     * declared with a media type of text/plain.
     *
     * @return The raw byte array representing the encoded EA certificate.
     * @throws IOException if an error occurs during certificate encoding.
     */
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public byte[] getCertificate() throws IOException {
        LOGGER.info("Fetching EA certificate");
        // Retrieves the certificate object and then gets its encoded form.
        return Setup.getEaCertificate().getEncoded();
    }
}