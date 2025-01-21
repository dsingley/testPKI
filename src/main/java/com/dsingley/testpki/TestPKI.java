package com.dsingley.testpki;

import lombok.Getter;
import lombok.NonNull;
import lombok.SneakyThrows;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;

import java.io.File;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import javax.naming.ldap.LdapName;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * The TestPKI class initializes a test Public Key Infrastructure (PKI) environment
 * with root CA, intermediate CA, server, and client certificates.
 * <p>
 * It generates truststore, server keystore, and client keystore files
 * and provides an SSL socket factory for server-side TLS communication.
 *
 * @see <a href="https://github.com/square/okhttp/tree/master/okhttp-tls">https://github.com/square/okhttp/tree/master/okhttp-tls</a>
 */
public class TestPKI {
    private static final String ORGANIZATIONAL_UNIT = "TestPKI";
    private static final String TRUSTSTORE_PASSWORD = "changeit";

    private final HeldCertificate rootCertificate;
    private final HeldCertificate intermediateCertificate;
    private final HeldCertificate serverCertificate;
    private final HeldCertificate clientCertificate;
    private final File truststoreFile;
    private final File caFile;
    @Getter private final String serverKeystorePassword;
    private final File serverKeystoreFile;
    private final File serverKeyFile;
    private final File serverCertFile;
    @Getter private final String clientKeystorePassword;
    private final File clientKeystoreFile;
    private final File clientKeyFile;
    private final File clientCertFile;

    public static void main(String[] args) {
        if (args.length < 1) {
            String keyTypes = Arrays.stream(KeyType.values())
                    .map(Enum::name)
                    .collect(Collectors.joining("|"));
            throw new IllegalArgumentException(String.format("Usage: java %s <baseDirectory> [%s]", TestPKI.class.getName(), keyTypes));
        }

        File baseDirectory = new File(args[0]);
        KeyType keyType =  args.length > 1 ? KeyType.valueOf(args[1]) : KeyType.ECDSA_256;

        TestPKI testPKI = new TestPKI(keyType, baseDirectory);

        System.out.printf("export TESTPKI_TRUSTSTORE_PATH=%s%n", testPKI.getTruststorePath());
        System.out.printf("export TESTPKI_TRUSTSTORE_PASSWORD='%s'%n", testPKI.getTruststorePassword());
        System.out.printf("export TESTPKI_SERVER_KEYSTORE_PATH=%s%n", testPKI.getServerKeystorePath());
        System.out.printf("export TESTPKI_SERVER_KEYSTORE_PASSWORD='%s'%n", testPKI.getServerKeystorePassword());
        System.out.printf("export TESTPKI_CLIENT_KEYSTORE_PATH=%s%n", testPKI.getClientKeystorePath());
        System.out.printf("export TESTPKI_CLIENT_KEYSTORE_PASSWORD='%s'%n", testPKI.getClientKeystorePassword());
    }

    public TestPKI() {
        this(KeyType.ECDSA_256, null);
    }

    @SneakyThrows
    public TestPKI(@NonNull KeyType keyType, File baseDirectory) {
        if (baseDirectory != null && (!baseDirectory.isDirectory() || !baseDirectory.canWrite())) {
            throw new IllegalArgumentException("baseDirectory, if provided, must be an existing writable directory: " + baseDirectory);
        }

        AtomicInteger serialNumber = new AtomicInteger(1);

        rootCertificate = buildHeldCertificate(keyType, new HeldCertificate.Builder()
                .commonName("Root CA")
                .organizationalUnit(ORGANIZATIONAL_UNIT)
                .serialNumber(serialNumber.getAndIncrement())
                .certificateAuthority(1)
        );

        intermediateCertificate = buildHeldCertificate(keyType, new HeldCertificate.Builder()
                .commonName("Intermediate CA")
                .organizationalUnit(ORGANIZATIONAL_UNIT)
                .serialNumber(serialNumber.getAndIncrement())
                .certificateAuthority(0)
                .signedBy(rootCertificate)
        );

        HeldCertificate.Builder serverCertificateBuilder = new HeldCertificate.Builder()
                .commonName("server")
                .organizationalUnit(ORGANIZATIONAL_UNIT)
                .serialNumber(serialNumber.getAndIncrement())
                .signedBy(intermediateCertificate);
        Set<String> subjectAlternativeNames = new TreeSet<>();
        subjectAlternativeNames.add("localhost");
        subjectAlternativeNames.add(InetAddress.getLocalHost().getHostName());
        subjectAlternativeNames.add(InetAddress.getLocalHost().getCanonicalHostName());
        for (String san : subjectAlternativeNames) {
            serverCertificateBuilder.addSubjectAlternativeName(san);
        }
        serverCertificate = buildHeldCertificate(keyType, serverCertificateBuilder);

        clientCertificate = buildHeldCertificate(keyType, new HeldCertificate.Builder()
                .commonName("client")
                .organizationalUnit(ORGANIZATIONAL_UNIT)
                .serialNumber(serialNumber.getAndIncrement())
                .signedBy(intermediateCertificate)
        );

        Map<String, HeldCertificate> caCertificates = new LinkedHashMap<>();
        caCertificates.put("root", rootCertificate);
        caCertificates.put("intermediate", intermediateCertificate);

        truststoreFile = createKeystoreFile(baseDirectory, "truststore", TRUSTSTORE_PASSWORD, caCertificates, null);
        caFile = createPemFile(baseDirectory, "ca", ".pem", caCertificates.values());

        serverKeystorePassword = randomPassword();
        serverKeystoreFile = createKeystoreFile(baseDirectory, "server", serverKeystorePassword, caCertificates, serverCertificate);
        serverKeyFile = createKeyPemFile(baseDirectory, "server", serverCertificate);
        serverCertFile = createPemFile(baseDirectory, "server", ".cert", Collections.singleton(serverCertificate));

        clientKeystorePassword = randomPassword();
        clientKeystoreFile = createKeystoreFile(baseDirectory, "client", clientKeystorePassword, caCertificates, clientCertificate);
        clientKeyFile = createKeyPemFile(baseDirectory, "client", clientCertificate);
        clientCertFile = createPemFile(baseDirectory, "client", ".cert", Collections.singleton(clientCertificate));
    }

    public SSLSocketFactory getServerSSLSocketFactory() {
        return new HandshakeCertificates.Builder()
                .addTrustedCertificate(rootCertificate.certificate())
                .addTrustedCertificate(intermediateCertificate.certificate())
                .heldCertificate(serverCertificate)
                .build()
                .sslSocketFactory();
    }

    public SSLSocketFactory getClientSSLSocketFactory() {
        return new HandshakeCertificates.Builder()
                .addTrustedCertificate(rootCertificate.certificate())
                .heldCertificate(clientCertificate) // , intermediateCertificate.certificate())
                .build()
                .sslSocketFactory();
    }

    public X509TrustManager getClientTrustManager() {
        return new HandshakeCertificates.Builder()
                .addTrustedCertificate(rootCertificate.certificate())
                .heldCertificate(clientCertificate) // , intermediateCertificate.certificate())
                .build()
                .trustManager();
    }

    public String getTruststorePath() {
        return truststoreFile.getAbsolutePath();
    }

    public String getTruststorePassword() {
        return TRUSTSTORE_PASSWORD;
    }

    public String getCaPath() {
        return caFile.getAbsolutePath();
    }

    public String getServerKeystorePath() {
        return serverKeystoreFile.getAbsolutePath();
    }

    public String getServerKeyPath() {
        return serverKeyFile.getAbsolutePath();
    }

    public String getServerCertPath() {
        return serverCertFile.getAbsolutePath();
    }

    public String getClientKeystorePath() {
        return clientKeystoreFile.getAbsolutePath();
    }

    public String getClientKeyPath() {
        return clientKeyFile.getAbsolutePath();
    }

    public String getClientCertPath() {
        return clientCertFile.getAbsolutePath();
    }

    private static String randomPassword() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static HeldCertificate buildHeldCertificate(KeyType keyType, HeldCertificate.Builder builder) {
        switch (keyType) {
            case ECDSA_256:
                builder.ecdsa256();
                return builder.build();
            case RSA_2048:
                builder.rsa2048();
                return builder.build();
            default:
                throw new RuntimeException("unexpected KeyType: " + keyType.name());
        }
    }

    @SneakyThrows
    private static File createKeystoreFile(File baseDirectory, String prefix, String password, Map<String, HeldCertificate> certificateEntryCertificates, HeldCertificate keyEntryCertificate) {
        File file = newFile(baseDirectory, prefix, ".pkcs12");

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password.toCharArray());
        for (Map.Entry<String, HeldCertificate> entry : certificateEntryCertificates.entrySet()) {
            keyStore.setCertificateEntry(entry.getKey(), entry.getValue().certificate());
        }
        if (keyEntryCertificate != null) {
            String alias = getCn(keyEntryCertificate.certificate());
            keyStore.setKeyEntry(alias, keyEntryCertificate.keyPair().getPrivate(), password.toCharArray(), new Certificate[]{keyEntryCertificate.certificate()});
        }

        try (FileOutputStream fos = new FileOutputStream(file.getAbsolutePath())) {
            keyStore.store(fos, password.toCharArray());
        }

        return file;
    }

    @SneakyThrows
    private static File createPemFile(File baseDirectory, String prefix, String suffix, Collection<HeldCertificate> certificates) {
        File file = newFile(baseDirectory, prefix, suffix);

        try (FileOutputStream fos = new FileOutputStream(file.getAbsolutePath())) {
            boolean first = true;
            for (HeldCertificate certificate : certificates) {
                if (first) {
                    first = false;
                } else {
                    fos.write("\n".getBytes());
                }
                fos.write(getComment(certificate).getBytes());
                fos.write(certificate.certificatePem().getBytes());
            }
        }

        return file;
    }

    private static String getComment(HeldCertificate certificate) {
        return String.format("# %s%n", certificate.certificate().getSubjectDN().getName());
    }

    @SneakyThrows
    private static File createKeyPemFile(File baseDirectory, String prefix, HeldCertificate certificate) {
        File file = newFile(baseDirectory, prefix, ".key");

        try (FileOutputStream fos = new FileOutputStream(file.getAbsolutePath())) {
            fos.write(String.format("# %s%n", certificate.certificate().getSubjectDN().getName()).getBytes());
            fos.write(certificate.privateKeyPkcs8Pem().getBytes());
        }

        return file;
    }

    @SneakyThrows
    private static File newFile(File baseDirectory, String prefix, String suffix) {
        File file;
        if (baseDirectory != null) {
            file = new File(baseDirectory, prefix + suffix);
        } else {
            file = File.createTempFile(prefix + "-", suffix);
            file.deleteOnExit();
        }
        return file;
    }

    @SneakyThrows
    private static String getCn(X509Certificate certificate) {
        return new LdapName(certificate.getSubjectDN().getName()).getRdns().stream()
                .filter(rdn -> rdn.getType().equalsIgnoreCase("CN"))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("no CN found"))
                .getValue()
                .toString();
    }
}
