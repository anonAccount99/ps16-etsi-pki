package eu.fbk.aleph.its.rootca.api;

import eu.fbk.aleph.its.rootca.config.Setup;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;

import java.io.IOException;

@Path("/certificate")
public class RootCert {
    private static final Logger LOGGER = Logger.getLogger(RootCert.class);
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public byte[] getCertificate() throws IOException {
        return Setup.getRootCACertificate().getEncoded();
    }
}