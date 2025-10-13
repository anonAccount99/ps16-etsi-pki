package eu.fbk.aleph.its.network;

import org.jboss.logging.Logger;
import java.net.*;

public class Listener {

    private static final Logger LOG = Logger.getLogger(Listener.class);
    private final int port;
    private final java.util.function.Consumer<DatagramPacket> handler;

    public Listener(int port, java.util.function.Consumer<DatagramPacket> handler) {
        this.port = port;
        this.handler = handler;
    }

    public void listen() throws Exception {
        byte[] buf = new byte[2048];
        try (DatagramSocket sock = new DatagramSocket(port)) {
            sock.setReuseAddress(true);
            while (true) {
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                sock.receive(pkt);
                handler.accept(pkt);
            }
        }
    }
}
