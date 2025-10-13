package eu.fbk.aleph.its.domain.denm.reception.etsi103097;

import eu.fbk.aleph.its.config.Setup;
import eu.fbk.aleph.its.network.Listener;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import static eu.fbk.aleph.its.utils.constant.ConfigConstants.*;
import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.DENBasicService;

/**
 * Listens for DENM messages over UDP, verifies ETSI-TS 103 097 signatures,
 * and dispatches only new events.
 */
public class DenmReceiver {

    private final Listener listener;
    private final CryptoManager cryptoManager;
    private final CertStore trustStore;
    private final CertStore certStore;

    // keep track of processed event IDs to avoid duplicates
    private final Map<String, Boolean> seenMap = new ConcurrentHashMap<>();

    private static final Logger logger = Logger.getLogger(DenmReceiver.class);

    /**
     * @param trustStore                   a store of root/CA certs
     * @param securedGroupMessageGenerator
     * @param certStore                    a store of intermediate/EE certs
     */
    public DenmReceiver(
            CertStore trustStore,
            ETSISecuredDataGenerator securedGroupMessageGenerator, CertStore certStore
    ) throws IOException, BadArgumentException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, BadCredentialsException {
        this.listener = new Listener(DENM_PORT, this::processPacket);
        this.trustStore = trustStore;
        this.certStore = certStore;

        // initialize crypto manager with BouncyCastle
        this.cryptoManager = new DefaultCryptoManager();
        this.cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));  // :contentReference[oaicite:0]{index=0}
    }

    /** Spins up a background thread to receive and process DENMs. */
    public void start() {
        Thread listenerThread = new Thread(() -> {
            logger.info("Starting DENM receiver on port " + DENM_PORT);
            try {
                // This will block and call processPacket(...) on each arrival
                listener.listen();
            } catch (Exception e) {
                logger.error("DENM listener encountered an error", e);
            }
        }, "DenmReceiver-Thread");
        listenerThread.setDaemon(true);
        listenerThread.start();
    }


    private void processPacket(DatagramPacket packet) {
        try {
            byte[] raw = Arrays.copyOf(packet.getData(), packet.getLength());
            EtsiTs103097DataSigned signedMessage = new EtsiTs103097DataSigned(raw);
            ETSISecuredDataGenerator securedMessageGenerator = Setup.getSecuredMessageGenerator();

            try {
                securedMessageGenerator.verifySignedData(
                        signedMessage,
                        certStore,
                        trustStore
                );
            } catch (BadArgumentException | IOException e) {
                throw new RuntimeException(e);
            } catch (SignatureException e) {
                logger.error("Signature failed verification:" + e.getMessage());
                return;
            }

            SignedData sd = (SignedData) signedMessage.getContent().getValue();

            if(!checkPsid(sd)){
                logger.error("PSID mismatch");
                return;
            }

            SignedDataPayload payloadWrapper = sd.getTbsData().getPayload();
            Ieee1609Dot2Data inner = payloadWrapper.getData();

            // 5) make sure it's unsecuredData and grab the raw DENM bytes
            Ieee1609Dot2Content c = inner.getContent();
            Opaque octs = (Opaque) c.getValue();
            byte[] denmBytes = octs.getData();

            // convert to string
            // String denmString = new String(denmBytes, StandardCharsets.UTF_8);
            String denmString = signedMessage.toString();
            
            // dedupe by the DENM string
            if (seenMap.containsKey(denmString)) {
                logger.debug("Duplicate DENM dropped: ");
                logger.info(ANSI_GREEN + "Received DENM: " + denmString + ANSI_RESET);
                return;
            }
            seenMap.put(denmString, Boolean.TRUE);

            // now handle it
            logger.info(ANSI_GREEN + "Received DENM: " + denmString + ANSI_RESET);

        } catch (IOException e) {
            // malformed or crypto failure – ignore or log
        } catch (Exception e) {
            // catch-all to prevent thread death
        }
    }

    private boolean checkPsid(SignedData sd) throws IOException {
        SignerIdentifier sid = sd.getSigner();
        Psid psid = sd.getTbsData().getHeaderInfo().getPsid();

        // 2) Cast the COERChoice value to SequenceOfCertificate
        SequenceOfCertificate seqCerts = (SequenceOfCertificate) sid.getValue();

        // 3) Pull out the Certificate array
        Certificate cert = (Certificate) seqCerts.getSequenceValues()[0];  // or however your COERSequenceOf exposes it
        PsidSsp certPsidSsp = (PsidSsp) cert.getToBeSigned().getAppPermissions().getSequenceValues()[0];
        logger.info("certPsid: " + certPsidSsp.getPsid());
        logger.info("expected PSID: " + DENBasicService.getValue());
        return Objects.equals(certPsidSsp.getPsid().getValue(), DENBasicService.getValue());
    }
}