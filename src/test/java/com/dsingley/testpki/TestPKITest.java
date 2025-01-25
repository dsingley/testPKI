package com.dsingley.testpki;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import lombok.NonNull;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

class TestPKITest {
    private final TestPKI testPKI = new TestPKI(KeyType.RSA_2048, null);

    @Nested
    class API {

        @Test
        void testServerCertificateIdentity() {
            TestPKICertificate certificate1 = testPKI.getOrCreateServerCertificate();
            TestPKICertificate certificate2 = testPKI.getOrCreateServerCertificate();
            assertAll(
                    () -> assertThat(certificate1).isNotNull(),
                    () -> assertThat(certificate2).isNotNull(),
                    () -> assertThat(certificate1).isEqualTo(certificate2)
            );
        }

        @Test
        void testClientCertificateIdentity() {
            TestPKICertificate certificate1 = testPKI.getOrCreateClientCertificate();
            TestPKICertificate certificate2 = testPKI.getOrCreateClientCertificate();
            assertAll(
                    () -> assertThat(certificate1).isNotNull(),
                    () -> assertThat(certificate2).isNotNull(),
                    () -> assertThat(certificate1).isEqualTo(certificate2)
            );
        }

        @Test
        void testCustomServerCertificate() throws Exception {
            TestPKICertificate certificate = testPKI.getOrCreateServerCertificate("custom-server");

            KeyStore keyStore = loadKeyStore(certificate.getOrCreateKeystoreFile(), certificate.getKeystorePassword());
            assertAll(
                    () -> assertThat(Collections.list(keyStore.aliases())).contains("custom-server"),
                    () -> assertThat(keyStore.isKeyEntry("custom-server")).isTrue()
            );

            X509Certificate serverCertificate = getCertificate(keyStore, "custom-server");
            assertThat(serverCertificate.getSubjectDN().getName()).startsWith("CN=custom-server");
        }

        @Test
        void testCustomServerCertificateWithSANs() throws Exception {
            Set<String> subjectAlternativeNames = new HashSet<>(Arrays.asList("san-1", "san-2"));
            TestPKICertificate testPKICertificate = testPKI.getOrCreateServerCertificate("san-server", subjectAlternativeNames);

            KeyStore keyStore = loadKeyStore(testPKICertificate.getOrCreateKeystoreFile(), testPKICertificate.getKeystorePassword());
            assertAll(
                    () -> assertThat(Collections.list(keyStore.aliases())).contains("san-server"),
                    () -> assertThat(keyStore.isKeyEntry("san-server")).isTrue()
            );

            X509Certificate serverCertificate = getCertificate(keyStore, "san-server");
            assertAll(
                    () -> assertThat(serverCertificate.getSubjectDN().getName()).startsWith("CN=san-server"),
                    () -> assertThat(getSubjectAlternativeNames(serverCertificate)).contains("san-1"),
                    () -> assertThat(getSubjectAlternativeNames(serverCertificate)).contains("san-2")
            );
        }

        @Test
        void testCustomClientCertificate() throws Exception {
            TestPKICertificate certificate = testPKI.getOrCreateClientCertificate("custom-client");

            KeyStore keyStore = loadKeyStore(certificate.getOrCreateKeystoreFile(), certificate.getKeystorePassword());
            assertAll(
                    () -> assertThat(Collections.list(keyStore.aliases())).contains("custom-client"),
                    () -> assertThat(keyStore.isKeyEntry("custom-client")).isTrue()
            );

            X509Certificate serverCertificate = getCertificate(keyStore, "custom-client");
            assertThat(serverCertificate.getSubjectDN().getName()).startsWith("CN=custom-client");
        }

        @Test
        void testSSLSocketFactoriesAndTrustManager() throws Exception{
            try (MockWebServer mockWebServer = new MockWebServer()) {
                mockWebServer.useHttps(testPKI.getOrCreateServerCertificate().getSSLSocketFactory());
                mockWebServer.requestClientAuth();

                mockWebServer.enqueue(new MockResponse.Builder()
                        .code(200)
                        .body("Hello, Test")
                        .build()
                );

                OkHttpClient client = new OkHttpClient.Builder()
                        .sslSocketFactory(testPKI.getOrCreateClientCertificate().getSSLSocketFactory(), testPKI.getOrCreateClientCertificate().getTrustManager())
                        .dns(new IPv4OnlyDns())
                        .build();

                Request request = new Request.Builder()
                        .url(mockWebServer.url("/"))
                        .build();

                try (Response response = client.newCall(request).execute()) {
                    RecordedRequest recordedRequest = mockWebServer.takeRequest(1, SECONDS);
                    assertThat(recordedRequest).isNotNull();

                    assertAll(
                            () -> assertThat(response.code()).isEqualTo(200),
                            () -> assertThat(response.body().string()).isEqualTo("Hello, Test"),
                            () -> assertThat(recordedRequest.getHandshake().peerPrincipal().toString()).startsWith("CN=client")
                    );
                }
            }
        }
    }

    @Nested
    class Files {

        @Nested
        class Trust {

            @Test
            void testTruststoreFile() throws Exception {
                File truststoreFile = testPKI.getOrCreateTruststoreFile();
                String truststorePassword = testPKI.getTruststorePassword();
                assertAll(
                        () -> assertThat(truststoreFile.getAbsolutePath()).matches(".*/truststore.*\\.pkcs12"),
                        () -> assertThat(truststoreFile).exists(),
                        () -> assertThat(truststorePassword).isNotEmpty()
                );

                KeyStore keyStore = loadKeyStore(truststoreFile, truststorePassword);
                assertAll(
                        () -> assertThat(Collections.list(keyStore.aliases())).contains("root", "intermediate"),
                        () -> assertThat(keyStore.isCertificateEntry("root")).isTrue(),
                        () -> assertThat(keyStore.isCertificateEntry("intermediate")).isTrue()
                );

                X509Certificate rootCertificate = getCertificate(keyStore, "root");
                assertThat(rootCertificate.getSubjectDN().getName()).startsWith("CN=Root CA");

                X509Certificate intermediateCertificate = getCertificate(keyStore, "intermediate");
                assertThat(intermediateCertificate.getSubjectDN().getName()).startsWith("CN=Intermediate CA");
            }

            @Test
            void testCaPemFile() throws Exception {
                File caPemFile = testPKI.getOrCreateCaPemFile();
                assertAll(
                        () -> assertThat(caPemFile.getAbsolutePath()).matches(".*/ca.*\\.pem"),
                        () -> assertThat(caPemFile).exists()
                );

                List<String> caPemLines = java.nio.file.Files.readAllLines(caPemFile.toPath());
                assertAll(
                        () -> assertThat(caPemLines).anyMatch(line -> line.contains("# CN=Root CA")),
                        () -> assertThat(caPemLines).anyMatch(line -> line.contains("# CN=Intermediate CA")),
                        () -> assertThat(caPemLines).filteredOn(line -> line.equals("-----BEGIN CERTIFICATE-----")).hasSize(2),
                        () -> assertThat(caPemLines).filteredOn(line -> line.equals("-----END CERTIFICATE-----")).hasSize(2)
                );
            }
        }

        @Nested
        class Server {

            @Test
            void testKeystoreFile() throws Exception {
                File keystoreFile = testPKI.getOrCreateServerCertificate().getOrCreateKeystoreFile();
                String keystorePassword = testPKI.getOrCreateServerCertificate().getKeystorePassword();
                assertAll(
                        () -> assertThat(keystoreFile.getAbsolutePath()).matches(".*/server.*\\.pkcs12"),
                        () -> assertThat(keystoreFile).exists(),
                        () -> assertThat(keystorePassword).matches("[A-Za-z0-9+/]+={0,2}")
                );

                KeyStore keyStore = loadKeyStore(keystoreFile, keystorePassword);
                assertAll(
                        () -> assertThat(Collections.list(keyStore.aliases())).contains("server"),
                        () -> assertThat(keyStore.isKeyEntry("server")).isTrue()
                );

                X509Certificate serverCertificate = getCertificate(keyStore, "server");
                assertAll(
                        () -> assertThat(serverCertificate.getSubjectDN().getName()).startsWith("CN=server"),
                        () -> assertThat(getSubjectAlternativeNames(serverCertificate)).contains("localhost")
                );
            }

            @Test
            void testCertPemFile() throws Exception {
                File certPemFile = testPKI.getOrCreateServerCertificate().getOrCreateCertPemFile();
                assertAll(
                        () -> assertThat(certPemFile.getAbsolutePath()).matches(".*/server.*\\.cert"),
                        () -> assertThat(certPemFile).exists()
                );

                List<String> certPemLines = java.nio.file.Files.readAllLines(certPemFile.toPath());
                assertAll(
                        () -> assertThat(certPemLines).anyMatch(line -> line.contains("# CN=server")),
                        () -> assertThat(certPemLines).filteredOn(line -> line.equals("-----BEGIN CERTIFICATE-----")).hasSize(1),
                        () -> assertThat(certPemLines).filteredOn(line -> line.equals("-----END CERTIFICATE-----")).hasSize(1)
                );
            }

            @Test
            void testKeyPemFile() throws Exception {
                File keyPemFile = testPKI.getOrCreateServerCertificate().getOrCreateKeyPemFile();
                assertAll(
                        () -> assertThat(keyPemFile.getAbsolutePath()).matches(".*/server.*\\.key"),
                        () -> assertThat(keyPemFile).exists()
                );

                List<String> keyPemLines = java.nio.file.Files.readAllLines(keyPemFile.toPath());
                assertAll(
                        () -> assertThat(keyPemLines).anyMatch(line -> line.contains("# CN=server")),
                        () -> assertThat(keyPemLines).filteredOn(line -> line.equals("-----BEGIN PRIVATE KEY-----")).hasSize(1),
                        () -> assertThat(keyPemLines).filteredOn(line -> line.equals("-----END PRIVATE KEY-----")).hasSize(1)
                );
            }
        }

        @Nested
        class Client {

            @Test
            void testKeystoreFile() throws Exception {
                File keystoreFile = testPKI.getOrCreateClientCertificate().getOrCreateKeystoreFile();
                String keystorePassword = testPKI.getOrCreateClientCertificate().getKeystorePassword();
                assertAll(
                        () -> assertThat(keystoreFile.getAbsolutePath()).matches(".*/client.*\\.pkcs12"),
                        () -> assertThat(keystoreFile).exists(),
                        () -> assertThat(keystorePassword).matches("[A-Za-z0-9+/]+={0,2}")
                );

                KeyStore keyStore = loadKeyStore(keystoreFile, keystorePassword);
                assertAll(
                        () -> assertThat(Collections.list(keyStore.aliases())).contains("client"),
                        () -> assertThat(keyStore.isKeyEntry("client")).isTrue()
                );

                X509Certificate clientCertificate = getCertificate(keyStore, "client");
                assertThat(clientCertificate.getSubjectDN().getName()).startsWith("CN=client");
            }

            @Test
            void testCertPemFile() throws Exception {
                File certPemFile = testPKI.getOrCreateClientCertificate().getOrCreateCertPemFile();
                assertAll(
                        () -> assertThat(certPemFile.getAbsolutePath()).matches(".*/client.*\\.cert"),
                        () -> assertThat(certPemFile).exists()
                );

                List<String> certPemLines = java.nio.file.Files.readAllLines(certPemFile.toPath());
                assertAll(
                        () -> assertThat(certPemLines).anyMatch(line -> line.contains("# CN=client")),
                        () -> assertThat(certPemLines).filteredOn(line -> line.equals("-----BEGIN CERTIFICATE-----")).hasSize(1),
                        () -> assertThat(certPemLines).filteredOn(line -> line.equals("-----END CERTIFICATE-----")).hasSize(1)
                );
            }

            @Test
            void testKeyPemFile() throws Exception {
                File keyPemFile = testPKI.getOrCreateClientCertificate().getOrCreateKeyPemFile();
                assertAll(
                        () -> assertThat(keyPemFile.getAbsolutePath()).matches(".*/client.*\\.key"),
                        () -> assertThat(keyPemFile).exists()
                );

                List<String> keyPemLines = java.nio.file.Files.readAllLines(keyPemFile.toPath());
                assertAll(
                        () -> assertThat(keyPemLines).anyMatch(line -> line.contains("# CN=client")),
                        () -> assertThat(keyPemLines).filteredOn(line -> line.equals("-----BEGIN PRIVATE KEY-----")).hasSize(1),
                        () -> assertThat(keyPemLines).filteredOn(line -> line.equals("-----END PRIVATE KEY-----")).hasSize(1)
                );
            }
        }
    }

    private static KeyStore loadKeyStore(File file, String password) throws Exception {
        try (InputStream is = java.nio.file.Files.newInputStream(file.toPath())) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(is, password.toCharArray());
            return keyStore;
        }
    }

    private static X509Certificate getCertificate(KeyStore keyStore, String alias) throws Exception {
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    private static List<String> getSubjectAlternativeNames(X509Certificate certificate) throws Exception {
        return certificate.getSubjectAlternativeNames().stream()
                .map(san -> (String) san.get(1))
                .collect(Collectors.toList());
    }

    private static class IPv4OnlyDns implements Dns {
        @NonNull
        @Override
        public List<InetAddress> lookup(@NonNull String hostname) throws UnknownHostException {
            return Dns.SYSTEM.lookup(hostname).stream()
                    .filter(inetAddress -> inetAddress instanceof Inet4Address)
                    .collect(Collectors.toList());
        }
    }
}
