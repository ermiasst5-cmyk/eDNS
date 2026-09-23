package com.ermia.edns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class DnsProxy {

    private static final String DNS_SERVER = "1.1.1.1";
    private static final int DNS_PORT = 53;

    public static byte[] forward(byte[] query, int length) throws IOException {
        DatagramSocket socket = new DatagramSocket();

        try {
            socket.setSoTimeout(3000);

            InetAddress server = InetAddress.getByName(DNS_SERVER);

            DatagramPacket request =
                    new DatagramPacket(
                            query,
                            length,
                            server,
                            DNS_PORT
                    );

            socket.send(request);

            byte[] response = new byte[4096];

            DatagramPacket reply =
                    new DatagramPacket(
                            response,
                            response.length
                    );

            socket.receive(reply);

            byte[] result = new byte[reply.getLength()];
            System.arraycopy(
                    reply.getData(),
                    reply.getOffset(),
                    result,
                    0,
                    reply.getLength()
            );

            return result;

        } finally {
            socket.close();
        }
    }
}
