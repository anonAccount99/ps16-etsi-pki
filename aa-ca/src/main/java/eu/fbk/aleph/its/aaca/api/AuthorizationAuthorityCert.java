package eu.fbk.aleph.its.aaca.api;

import eu.fbk.aleph.its.aaca.config.Setup;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.jboss.logging.Logger;

import java.io.IOException;

/**
 * Defines a JAX-RS resource endpoint for retrieving the Authorization Authority (AA) certificate.
 * This class exposes the AA's certificate via a RESTful API.
 */
@Path("/certificate")
public class AuthorizationAuthorityCert {
    /**
     * Logger instance for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AuthorizationAuthorityCert.class);

    /**
     * Handles HTTP GET requests to the /certificate path.
     * Retrieves the pre-configured Authorization Authority (AA) certificate
     * from the Setup class and returns it serialized as JSON.
     *
     * @return The AA's EtsiTs103097Certificate, which will be serialized to JSON.
     */
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public byte[] getCertificate() throws IOException, BadArgumentException {
        LOGGER.info("Fetching AA certificate and Group Public Key");
        return Setup.getAaCertificate().getEncoded();
    }
}