package eu.fbk.aleph.its.network;

import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.*;
import java.util.List;

public class Broadcast {

    private final static Logger LOGGER = Logger.getLogger(Broadcast.class);

    /**
     * Broadcasts a Denm message over UDP on the container's eth0 (obus-net) interface.
     *
     * @param messageBytes the byte array of the Denm message.
     * @param port         the destination UDP port.
     * @throws IOException if an I/O error occurs.
     */
    public void broadcastDENM(byte[] messageBytes, int port) throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setBroadcast(true);

            NetworkInterface nif = NetworkInterface.getByName("eth0");
            if (nif == null) {
                throw new SocketException("Interface eth0 not found");
            }

            InetAddress broadcastAddress = getInetAddress(nif);
            DatagramPacket packet = new DatagramPacket(
                    messageBytes,
                    messageBytes.length,
                    broadcastAddress,
                    port
            );
            socket.send(packet);
            /*

            LOGGER.info(
                    "Broadcast message sent to "
                            + broadcastAddress.getHostAddress() + ":" + port
                            + " on eth0 (" + nif.getName() + ")"
            );

             */
        }
    }

    private static InetAddress getInetAddress(NetworkInterface nif) throws SocketException {
        InetAddress broadcastAddress = null;
        List<InterfaceAddress> addrs = nif.getInterfaceAddresses();
        for (InterfaceAddress ifAddr : addrs) {
            if (ifAddr.getAddress() instanceof Inet4Address) {
                InetAddress bc = ifAddr.getBroadcast();
                if (bc != null) {
                    broadcastAddress = bc;
                    break;
                }
            }
        }

        if (broadcastAddress == null) {
            throw new SocketException("No broadcast address found on eth0");
        }
        return broadcastAddress;
    }

}
