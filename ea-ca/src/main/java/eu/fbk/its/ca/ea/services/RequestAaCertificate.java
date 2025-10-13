package eu.fbk.its.ca.ea.services;

import eu.fbk.its.ca.ea.utils.constants.ConfigConstants;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.certificateservices.custom.c2x.groupsig.cert.AACert;
import org.jboss.logging.Logger;


public class RequestAaCertificate {

    private AACert aaCertificate;
    private static final Logger LOGGER = Logger.getLogger(RequestAaCertificate.class);

    public RequestAaCertificate() {
        Client client = ClientBuilder.newClient();
        try {
            Response response = client.target(ConfigConstants.DEFAULT_AA_CERTIFICATE_URL)
                    .request(MediaType.TEXT_PLAIN)
                    .get();
            if (response.getStatus() == Response.Status.OK.getStatusCode()) {
                byte[] aaCertificateBytes = response.readEntity(byte[].class);
                this.aaCertificate = new AACert(aaCertificateBytes);
                LOGGER.info("AA certificate: " + this.aaCertificate);
            } else {
                LOGGER.error("ERROR: could not retrieve AA certificate. HTTP status: " + response.getStatus());
            }
        } catch (Exception e) {
            LOGGER.error("ERROR: could not retrieve AA certificate.", e);
        } finally {
            client.close();
        }
    }

    public AACert getAaCertificate() {
        return aaCertificate;
    }
}