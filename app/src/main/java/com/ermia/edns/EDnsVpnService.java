package com.ermia.edns;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;

public class EDnsVpnService extends VpnService {

    private static final String CHANNEL_ID = "edns_vpn";
    private ParcelFileDescriptor vpnInterface;
    private Thread worker;
    private volatile boolean running;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        createNotificationChannel();
        startForeground(1001, notification());

        if (worker == null || !worker.isAlive()) {
            running = true;
            worker = new Thread(this::runVpn, "eDNS-VPN");
            worker.start();
        }

        return START_STICKY;
    }

    private void runVpn() {
        try {
            vpnInterface = new Builder()
                    .setSession("eDNS")
                    .addAddress("10.0.0.2", 32)
                    .addRoute("1.1.1.1", 32)
                    .addDnsServer("1.1.1.1")
                    .establish();

            if (vpnInterface == null) {
                return;
            }

            FileInputStream input =
                    new FileInputStream(vpnInterface.getFileDescriptor());

            FileOutputStream output =
                    new FileOutputStream(vpnInterface.getFileDescriptor());

            byte[] packet = new byte[32767];

            while (running) {
                int length = input.read(packet);

                if (length <= 0) {
                    continue;
                }

                byte[] data = Arrays.copyOf(packet, length);

                byte[] response = handleDnsPacket(data);

                if (response != null) {
                    output.write(response);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] handleDnsPacket(byte[] packet) {
        if (packet.length < 28) {
            return null;
        }

        int version = (packet[0] >> 4) & 0x0F;

        if (version != 4) {
            return null;
        }

        int ihl = (packet[0] & 0x0F) * 4;

        if (packet.length < ihl + 8) {
            return null;
        }

        int protocol = packet[9] & 0xFF;

        // UDP only
        if (protocol != 17) {
            return null;
        }

        int udpOffset = ihl;

        int sourcePort =
                ((packet[udpOffset] & 0xFF) << 8)
                        | (packet[udpOffset + 1] & 0xFF);

        int destinationPort =
                ((packet[udpOffset + 2] & 0xFF) << 8)
                        | (packet[udpOffset + 3] & 0xFF);

        if (destinationPort != 53) {
            return null;
        }

        int dnsOffset = udpOffset + 8;

        if (dnsOffset >= packet.length) {
            return null;
        }

        byte[] query =
                Arrays.copyOfRange(packet, dnsOffset, packet.length);

        try {
            DatagramSocket socket = new DatagramSocket();

            try {
                // Prevent the DNS socket from going through our own VPN.
                protect(socket);

                socket.setSoTimeout(3000);

                DatagramPacket request =
                        new DatagramPacket(
                                query,
                                query.length,
                                InetAddress.getByName("1.1.1.1"),
                                53
                        );

                socket.send(request);

                byte[] buffer = new byte[4096];

                DatagramPacket reply =
                        new DatagramPacket(buffer, buffer.length);

                socket.receive(reply);

                byte[] dnsResponse =
                        Arrays.copyOf(
                                reply.getData(),
                                reply.getLength()
                        );

                return buildUdpIpv4Response(
                        packet,
                        ihl,
                        sourcePort,
                        destinationPort,
                        dnsResponse
                );

            } finally {
                socket.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] buildUdpIpv4Response(
            byte[] request,
            int ihl,
            int sourcePort,
            int destinationPort,
            byte[] dns
    ) {
        int udpLength = 8 + dns.length;
        int totalLength = ihl + udpLength;

        byte[] response = new byte[totalLength];

        // Copy original IP header.
        System.arraycopy(request, 0, response, 0, ihl);

        // Swap source/destination IP.
        for (int i = 0; i < 4; i++) {
            response[12 + i] = request[16 + i];
            response[16 + i] = request[12 + i];
        }

        // UDP source/destination ports are reversed.
        write16(response, ihl, destinationPort);
        write16(response, ihl + 2, sourcePort);
        write16(response, ihl + 4, udpLength);

        // UDP checksum = 0 for IPv4 UDP.
        write16(response, ihl + 6, 0);

        System.arraycopy(
                dns,
                0,
                response,
                ihl + 8,
                dns.length
        );

        // IPv4 total length.
        write16(response, 2, totalLength);

        // New IP identification.
        response[4] = request[4];
        response[5] = request[5];

        // Clear fragmentation flags/offset.
        response[6] = 0;
        response[7] = 0;

        // TTL.
        response[8] = 64;

        // UDP.
        response[9] = 17;

        // Recalculate IPv4 header checksum.
        response[10] = 0;
        response[11] = 0;

        int checksum = ipChecksum(response, 0, ihl);
        write16(response, 10, checksum);

        return response;
    }

    private static void write16(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >> 8) & 0xFF);
        data[offset + 1] = (byte) (value & 0xFF);
    }

    private static int ipChecksum(
            byte[] data,
            int offset,
            int length
    ) {
        long sum = 0;

        for (int i = 0; i < length; i += 2) {
            int high = data[offset + i] & 0xFF;
            int low =
                    (i + 1 < length)
                            ? data[offset + i + 1] & 0xFF
                            : 0;

            sum += (high << 8) | low;

            while ((sum >> 16) != 0) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        return (int) (~sum) & 0xFFFF;
    }

    private Notification notification() {
        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("eDNS")
                .setContentText("Secure DNS is active")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel =
                    new NotificationChannel(
                            CHANNEL_ID,
                            "eDNS VPN",
                            NotificationManager.IMPORTANCE_LOW
                    );

            NotificationManager manager =
                    getSystemService(NotificationManager.class);

            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    @Override
    public void onDestroy() {
        running = false;

        if (worker != null) {
            worker.interrupt();
            worker = null;
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }

            vpnInterface = null;
        }

        super.onDestroy();
    }
}
