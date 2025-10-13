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
 * Represents a request mechanism to fetch the Enrollment Authority (EA) certificate.
 * Upon instantiation, this class attempts to retrieve the EA certificate
 * from a configured remote endpoint and stores it internally.
 */
public class RequestEaCertificate {
    /**
     * Stores the fetched Enrollment Authority certificate. May be null if fetching fails.
     */
    private EtsiTs103097Certificate eaCertificate;
    /**
     * Logger instance for this class. Note: Logger references RequestEnrollmentCertificate class.
     */
    private static final Logger LOGGER = Logger.getLogger(RequestEaCertificate.class);

    /**
     * Constructs an instance and immediately attempts to fetch the EA certificate.
     * It uses a JAX-RS client to send a GET request to the URL defined in
     * Setup.DEFAULT_EA_CERTIFICATE_URL. Handles potential errors during the request
     * and ensures the client resource is closed.
     */
    public RequestEaCertificate() {
        Client client = ClientBuilder.newClient();
        try {
            Response response = client.target(ConfigConstants.DEFAULT_EA_CERTIFICATE_URL)
                    .request(MediaType.TEXT_PLAIN)
                    .get();
            if (response.getStatus() == Response.Status.OK.getStatusCode()) {
                byte[] eaCertificateBytes = response.readEntity(byte[].class);
                this.eaCertificate = new EtsiTs103097Certificate(eaCertificateBytes);
                LOGGER.info("EA certificate: " + this.eaCertificate);
            } else {
                LOGGER.error("ERROR: could not retrieve EA certificate. HTTP status: " + response.getStatus());
            }
        } catch (Exception e) {
            LOGGER.error("ERROR: could not retrieve EA certificate.", e);
        } finally {
            client.close();
        }
    }

    /**
     * Returns the fetched Enrollment Authority (EA) certificate.
     *
     * @return The EtsiTs103097Certificate object representing the EA certificate,
     * or null if the certificate could not be fetched during object construction.
     */
    public EtsiTs103097Certificate getEaCertificate() {
        return eaCertificate;
    }
}