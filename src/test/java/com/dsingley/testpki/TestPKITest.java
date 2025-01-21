package com.dsingley.testpki;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import okhttp3.Call;
import okhttp3.Dns;
import okhttp3.OkHttp;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

class TestPKITest {
    private final TestPKI testPKI = new TestPKI();

    static class IPv4OnlyDns implements Dns {
        @NotNull
        @Override
        public List<InetAddress> lookup(@NotNull String hostname) throws UnknownHostException {
            return Dns.SYSTEM.lookup(hostname).stream()
                    .filter(inetAddress -> inetAddress instanceof Inet4Address)
                    .collect(Collectors.toList());
        }
    }

    @Nested
    class Objects {

        @Test
        void x() throws Exception {
            // Create the root for client and server to trust. We could also use different roots for each!
            HeldCertificate rootCertificate = new HeldCertificate.Builder()
                    .certificateAuthority(0)
                    .build();

// Create a server certificate and a server that uses it.
            HeldCertificate serverCertificate = new HeldCertificate.Builder()
                    .commonName("ingen")
//                    .addSubjectAlternativeName(server.getHostName())
                    .signedBy(rootCertificate)
                    .build();
            HandshakeCertificates serverCertificates = new HandshakeCertificates.Builder()
                    .addTrustedCertificate(rootCertificate.certificate())
                    .heldCertificate(serverCertificate)
                    .build();
            MockWebServer server = new MockWebServer();
            server.useHttps(serverCertificates.sslSocketFactory());
            server.requestClientAuth();
            server.enqueue(new MockResponse());
            server.start();

// Create a client certificate and a client that uses it.
            HeldCertificate clientCertificate = new HeldCertificate.Builder()
                    .commonName("ianmalcolm")
                    .signedBy(rootCertificate)
                    .build();
            HandshakeCertificates clientCertificates = new HandshakeCertificates.Builder()
                    .addTrustedCertificate(rootCertificate.certificate())
                    .heldCertificate(clientCertificate)
                    .build();
            OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager())
                    .dns(new IPv4OnlyDns())
                    .build();

// Connect 'em all together. Certificates are exchanged in the handshake.
            Call call = client.newCall(new Request.Builder()
                    .url(server.url("/"))
                    .build());
            Response response = call.execute();
            System.out.println(response.handshake().peerPrincipal());
            RecordedRequest recordedRequest = server.takeRequest();
            System.out.println(recordedRequest.getHandshake().peerPrincipal());
        }

        @Test
        void testGetServerSSLSocketFactory() throws Exception{
            try (MockWebServer mockWebServer = new MockWebServer()) {
                mockWebServer.useHttps(testPKI.getServerSSLSocketFactory());
                mockWebServer.requestClientAuth();

                mockWebServer.enqueue(new MockResponse.Builder()
                        .code(200)
                        .body("Hello, Test")
                        .build()
                );

                mockWebServer.start();
                System.out.println(mockWebServer.url("/"));

                OkHttpClient client = new OkHttpClient.Builder()
                        .sslSocketFactory(testPKI.getClientSSLSocketFactory(), testPKI.getClientTrustManager())
                        .dns(new IPv4OnlyDns())
                        .build();

                Request request = new Request.Builder()
                        .url(mockWebServer.url("/"))
                        .build();

                try (Response response = client.newCall(request).execute()) {
                    RecordedRequest recordedRequest = mockWebServer.takeRequest(1, SECONDS);

                    assertAll(
                            () -> assertThat(response.code()).isEqualTo(200),
                            () -> assertThat(response.body().string()).isEqualTo("Hello, Test"),
                            () -> assertThat(recordedRequest.getHandshake().peerPrincipal()).isEqualTo("x")
                    );
                }
            }
        }
    }

    @Nested
    class Files {

        @Test
        void testGetTruststorePath() {
            String truststorePath = testPKI.getTruststorePath();
            assertAll(
                    () -> assertThat(truststorePath).matches(".*/truststore.*\\.pkcs12"),
                    () -> assertThat(Paths.get(truststorePath)).exists()
            );
        }

        @Test
        void testGetTruststorePassword() {
            assertThat(testPKI.getTruststorePassword()).isEqualTo("changeit");
        }

        @Test
        void testGetCaPath() {
            String caPath = testPKI.getCaPath();
            assertAll(
                    () -> assertThat(caPath).matches(".*/ca.*\\.pem"),
                    () -> assertThat(Paths.get(caPath)).exists()
            );
        }

        @Test
        void testGetServerKeystorePath() {
            String serverKeystorePath = testPKI.getServerKeystorePath();
            assertAll(
                    () -> assertThat(serverKeystorePath).matches(".*/server.*\\.pkcs12"),
                    () -> assertThat(Paths.get(serverKeystorePath)).exists()
            );
        }

        @Test
        void testGetServerKeystorePassword() {
            assertThat(testPKI.getServerKeystorePassword()).matches("[A-Za-z0-9+/]+={0,2}");
        }

        @Test
        void testGetServerKeyPath() {
            String serverKeyPath = testPKI.getServerKeyPath();
            assertAll(
                    () -> assertThat(serverKeyPath).matches(".*/server.*\\.key"),
                    () -> assertThat(Paths.get(serverKeyPath)).exists()
            );
        }

        @Test
        void testGetServerCertPath() {
            String serverCertPath = testPKI.getServerCertPath();
            assertAll(
                    () -> assertThat(serverCertPath).matches(".*/server.*\\.cert"),
                    () -> assertThat(Paths.get(serverCertPath)).exists()
            );
        }

        @Test
        void testGetClientKeystorePath() {
            String clientKeystorePath = testPKI.getClientKeystorePath();
            assertAll(
                    () -> assertThat(clientKeystorePath).matches(".*/client.*\\.pkcs12"),
                    () -> assertThat(Paths.get(clientKeystorePath)).exists()
            );
        }

        @Test
        void testGetClientKeystorePassword() {
            assertThat(testPKI.getClientKeystorePassword()).matches("[A-Za-z0-9+/]+={0,2}");
        }

        @Test
        void testGetClientKeyPath() {
            String clientKeyPath = testPKI.getClientKeyPath();
            assertAll(
                    () -> assertThat(clientKeyPath).matches(".*/client.*\\.key"),
                    () -> assertThat(Paths.get(clientKeyPath)).exists()
            );
        }

        @Test
        void testGetClientCertPath() {
            String clientCertPath = testPKI.getClientCertPath();
            assertAll(
                    () -> assertThat(clientCertPath).matches(".*/client.*\\.cert"),
                    () -> assertThat(Paths.get(clientCertPath)).exists()
            );
        }
    }
}
