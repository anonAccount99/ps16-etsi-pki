package eu.fbk.aleph.its.domain.denm.transmission.groupsig;

import com.ibm.jgroupsig.MemKey;
import com.ibm.jgroupsig.PS16;
import eu.fbk.aleph.its.network.Broadcast;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

public class DenmTransmitter {
    private static final Logger LOGGER = Logger.getLogger(DenmTransmitter.class);

    private static final int DENM_PORT = 30000;

    /**
     * Retransmission profile (milliseconds):
     *  - 10 × 1 000 ms (1 Hz for 10 s)
     *  -  5 × 5 000 ms
     *  -  5 × 10 000 ms
     *  -  3 × 30 000 ms
     */
    private static final long[] RETRANSMISSION_INTERVALS_MS = {
            1_000,1_000,1_000,1_000,1_000,1_000,1_000,1_000,1_000,1_000,
            5_000,5_000,5_000,5_000,5_000,
            10_000,10_000,10_000,10_000,10_000,
            30_000,30_000,30_000
    };

    private final Broadcast broadcaster = new Broadcast();
    private final ScheduledExecutorService scheduler =
            Executors.newScheduledThreadPool(1);

    /** actionId → list of scheduled retransmission tasks */
    private final Map<String, List<ScheduledFuture<?>>> pendingTransmissions =
            new ConcurrentHashMap<>();

    /**
     * Trigger a brand‑new Denm event.
     * @param actionId a unique ID for this event (must be globally unique)
     */
    public void triggerNewEvent(
            String actionId,
            PS16 groupUser,
            MemKey memKey
    ) {
        try {
            byte[] data = Hex.decode("010203040506");
            DenmGenerator gen =
                    new DenmGenerator(
                            groupUser,
                            memKey,
                            data
                    );
            EtsiTs103097DataSigned denm = gen.genDENMessage();
            System.out.println("Generated Denm" + denm);
            final byte[] payload = denm.getEncoded();

            broadcastPayload(payload);

            scheduleRetransmissions(actionId, payload);
        } catch (IOException | BadArgumentException
                 | SignatureException e) {
            LOGGER.error("Failed to generate/send initial Denm for " + actionId, e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Update an existing event: cancel old schedule, generate a fresh Denm
     * (same actionId internally) and re‑schedule.
     */
    public void updateEvent(
            String actionId,
            PS16 groupUser,
            MemKey memKey
    ) {
        cancelEvent(actionId);

        try {
            byte[] data = Hex.decode("010203040506");
            DenmGenerator gen =
                    new DenmGenerator(
                            groupUser,
                            memKey,
                            data
                    );
            EtsiTs103097DataSigned denm = gen.genDENMessage();
            final byte[] payload = denm.getEncoded();

            broadcastPayload(payload);

            scheduleRetransmissions(actionId, payload);
        } catch (IOException | BadArgumentException
                 | SignatureException e) {
            LOGGER.error("Failed to generate/send updated Denm for " + actionId, e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Cancel an event: stops all future retransmissions.
     * @param actionId the same ID you used in triggerNewEvent()
     */
    public void cancelEvent(String actionId) {
        List<ScheduledFuture<?>> futures = pendingTransmissions.remove(actionId);
        if (futures != null) {
            for (ScheduledFuture<?> f : futures) {
                f.cancel(false);
            }
            LOGGER.info("Cancelled all pending retransmissions for " + actionId);
        }
    }

    /** Schedule the retransmission tasks according to our intervals profile. */
    private void scheduleRetransmissions(String actionId, byte[] payload) {
        List<ScheduledFuture<?>> futures = new ArrayList<>(RETRANSMISSION_INTERVALS_MS.length);
        long cumulativeDelay = 0;

        for (long interval : RETRANSMISSION_INTERVALS_MS) {
            cumulativeDelay += interval;
            ScheduledFuture<?> task = scheduler.schedule(() -> {
                broadcastPayload(payload);
            }, cumulativeDelay, TimeUnit.MILLISECONDS);
            futures.add(task);
        }

        pendingTransmissions.put(actionId, futures);
        LOGGER.info("Scheduled " + futures.size() + " retransmissions for " + actionId);
    }

    /** Actually send the bytes over UDP. */
    public void broadcastPayload(byte[] payload) {
        try {
            broadcaster.broadcastDENM(payload, DENM_PORT);
        } catch (IOException e) {
            LOGGER.error("Error broadcasting Denm payload", e);
        }
    }
}
