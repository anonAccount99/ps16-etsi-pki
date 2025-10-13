package eu.fbk.aleph.its.aaca.services.etsi103097;

import eu.fbk.aleph.its.aaca.config.Setup;
import eu.fbk.aleph.its.aaca.utils.constants.ConfigConstants;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.jboss.logging.Logger;

/**
 * Represents a request mechanism to fetch the Registration Authority (RA) certificate.
 * Upon instantiation, this class attempts to retrieve the RA certificate
 * from a configured remote endpoint and stores it internally.
 */
public class RequestRaCertificate {
    /**
     * Stores the fetched Registration Authority certificate. May be null if fetching fails.
     */
    private EtsiTs103097Certificate raCertificate;
    /**
     * Logger instance for this class. Note: Logger references RequestEnrollmentCertificate class.
     */
    private static final Logger LOGGER = Logger.getLogger(RequestRaCertificate.class);

    /**
     * Constructs an instance and immediately attempts to fetch the RA certificate.
     * It uses a JAX-RS client to send a GET request to the URL defined in
     * Setup.DEFAULT_RA_CERTIFICATE_URL.
     */
    public RequestRaCertificate() {
        Client client = ClientBuilder.newClient();
        try {
            Response response = client.target(ConfigConstants.DEFAULT_RA_CERTIFICATE_URL)
                    .request(MediaType.TEXT_PLAIN)
                    .get();
            if (response.getStatus() == Response.Status.OK.getStatusCode()) {
                byte[] raCertificateBytes = response.readEntity(byte[].class);
                this.raCertificate = new EtsiTs103097Certificate(raCertificateBytes);
                LOGGER.info("RA certificate: " + this.raCertificate);
            } else {
                LOGGER.error("ERROR: could not retrieve RA certificate. HTTP status: " + response.getStatus());
            }
        } catch (Exception e) {
            LOGGER.error("ERROR: could not retrieve RA certificate.", e);
        } finally {
            client.close();
        }
    }

    /**
     * Returns the fetched Registration Authority (RA) certificate.
     *
     * @return The EtsiTs103097Certificate object representing the RA certificate,
     * or null if the certificate could not be fetched during object construction.
     */
    public EtsiTs103097Certificate getRaCertificate() {
        return raCertificate;
    }
}