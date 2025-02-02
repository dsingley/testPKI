package com.dsingley.testpki;

import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.Synchronized;
import lombok.extern.slf4j.Slf4j;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.File;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import javax.naming.ldap.LdapName;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

/**
 * The TestPKI class initializes a test Public Key Infrastructure (PKI) environment
 * with root and intermediate certificate authorities.
 * <p>
 * It can create persistent or temporary PKCS12 keystore and/or PEM files for
 * trusted certificates, server certificates and keys, and client certificates and keys.
 * <p>
 * It can provide {@link SSLSocketFactory} and {@link X509TrustManager} instances to use
 * for TLS communication.
 *
 * @see <a href="https://github.com/square/okhttp/tree/master/okhttp-tls">OkHttp TLS</a>
 */
@Slf4j
public class TestPKI {
    private static final String ORGANIZATIONAL_UNIT = "TestPKI";
    private static final String TRUSTSTORE_PASSWORD = "changeit";

    private final KeyType keyType;
    private final File baseDirectory;
    private final AtomicLong serialNumber;
    private final Map<String, HeldCertificate> caCertificates;
    private final HeldCertificate rootCertificate;
    private final HeldCertificate intermediateCertificate;
    private final Map<String, TestPKICertificate> issuedCertificates;
    private File truststoreFile;
    private File caPemFile;

    public static void main(String[] args) {
        CommandLineOptions commandLineOptions = CommandLineOptions.parse(args);
        TestPKI testPKI = new TestPKI(commandLineOptions.getKeyType(), commandLineOptions.getBaseDirectory());

        File truststoreFile = testPKI.getOrCreateTruststoreFile();
        File caPemFile = testPKI.getOrCreateCaPemFile();

        TestPKICertificate serverCertificate = testPKI.getOrCreateServerCertificate();
        File serverKeystoreFile = serverCertificate.getOrCreateKeystoreFile();
        File serverCertPemFile = serverCertificate.getOrCreateCertPemFile();
        File serverKeyPemFile = serverCertificate.getOrCreateKeyPemFile();

        TestPKICertificate clientCertificate = testPKI.getOrCreateClientCertificate();
        File clientKeystoreFile = clientCertificate.getOrCreateKeystoreFile();
        File clientCertPemFile = clientCertificate.getOrCreateCertPemFile();
        File clientKeyPemFile = clientCertificate.getOrCreateKeyPemFile();

        if (commandLineOptions.isExport()) {
            String prefix = commandLineOptions.getVariableNamePrefix();
            if (prefix == null) {
                prefix = "";
            } else if (!prefix.isEmpty() && !prefix.endsWith("_")) {
                prefix = prefix.toUpperCase() + "_";
            }
            System.out.printf("export %sTRUSTSTORE_PATH=%s%n", prefix, truststoreFile.getAbsolutePath());
            System.out.printf("export %sTRUSTSTORE_PASSWORD='%s'%n", prefix, testPKI.getTruststorePassword());
            System.out.printf("export %sCA_PATH=%s%n", prefix, caPemFile.getAbsolutePath());
            System.out.printf("export %sSERVER_KEYSTORE_PATH=%s%n", prefix, serverKeystoreFile.getAbsolutePath());
            System.out.printf("export %sSERVER_KEYSTORE_PASSWORD='%s'%n", prefix, serverCertificate.getKeystorePassword());
            System.out.printf("export %sSERVER_CERT_PATH=%s%n", prefix, serverCertPemFile.getAbsolutePath());
            System.out.printf("export %sSERVER_KEY_PATH=%s%n", prefix, serverKeyPemFile.getAbsolutePath());
            System.out.printf("export %sCLIENT_KEYSTORE_PATH=%s%n", prefix, clientKeystoreFile.getAbsolutePath());
            System.out.printf("export %sCLIENT_KEYSTORE_PASSWORD='%s'%n", prefix, clientCertificate.getKeystorePassword());
            System.out.printf("export %sCLIENT_CERT_PATH=%s%n", prefix, clientCertPemFile.getAbsolutePath());
            System.out.printf("export %sCLIENT_KEY_PATH=%s%n", prefix, clientKeyPemFile.getAbsolutePath());
        }
    }

    /**
     * Constructs a TestPKI instance that will use the specified key algorithm and size, and create files in
     * the specified base directory. If a base directory is not provided, temporary files will be created.
     *
     * @param keyType       the desired key algorithm and size
     * @param baseDirectory the directory in which to create files (optional)
     */
    @SneakyThrows
    public TestPKI(@NonNull KeyType keyType, @Nullable File baseDirectory) {
        this.keyType = keyType;
        if (baseDirectory != null && !Files.isDirectory(baseDirectory.toPath())) {
            throw new IllegalArgumentException("baseDirectory, if specified, must be an existing directory: " + baseDirectory);
        }
        this.baseDirectory = baseDirectory;
        serialNumber = new AtomicLong(1);
        caCertificates = new LinkedHashMap<>();

        rootCertificate = newCertificate(new HeldCertificate.Builder()
                .commonName("Root CA")
                .organizationalUnit(ORGANIZATIONAL_UNIT)
                .serialNumber(serialNumber.getAndIncrement())
                .certificateAuthority(1)
        );
        caCertificates.put("root", rootCertificate);

        intermediateCertificate = newCertificate(new HeldCertificate.Builder()
                .commonName("Intermediate CA")
                .organizationalUnit(ORGANIZATIONAL_UNIT)
                .serialNumber(serialNumber.getAndIncrement())
                .certificateAuthority(0)
                .signedBy(rootCertificate)
        );
        caCertificates.put("intermediate", intermediateCertificate);

        issuedCertificates = new ConcurrentHashMap<>();
    }

    /**
     * Get a reference to a keystore file containing CA certificates, creating
     * the file on disk if not already created.
     *
     * @return the truststore file as a File object
     */
    @Synchronized
    public File getOrCreateTruststoreFile() {
        if (truststoreFile != null) {
            return truststoreFile;
        }
        truststoreFile = createKeystoreFile("truststore", TRUSTSTORE_PASSWORD, null);
        return truststoreFile;
    }

    /**
     * Retrieve the password for the truststore file accessible via
     * {@link TestPKI#getOrCreateTruststoreFile()}.
     *
     * @return the truststore password as a String
     */
    public String getTruststorePassword() {
        return TRUSTSTORE_PASSWORD;
    }

    /**
     * Get a reference to a PEM file containing CA certificates, creating
     * the file on disk if not already created.
     *
     * @return the CA PEM file as a File object
     */
    @Synchronized
    public File getOrCreateCaPemFile() {
        if (caPemFile != null) {
            return caPemFile;
        }
        caPemFile = createPemFile("ca", ".pem", caCertificates.values(), c -> c.certificatePem().getBytes());
        return caPemFile;
    }

    /**
     * Get a reference to a {@link TestPKICertificate} for a default server certificate,
     * issuing a new certificate if not already created.
     *
     * @return the default server certificate as a TestPKICertificate
     */
    @SneakyThrows
    public TestPKICertificate getOrCreateServerCertificate() {
        Set<String> subjectAlternativeNames = new TreeSet<>();
        subjectAlternativeNames.add("localhost");
        subjectAlternativeNames.add(InetAddress.getLocalHost().getHostName());
        subjectAlternativeNames.add(InetAddress.getLocalHost().getCanonicalHostName());
        return getOrCreateServerCertificate("server", subjectAlternativeNames);
    }

    /**
     * Get a reference to a {@link TestPKICertificate} for a server certificate with
     * the specified common name (CN=), issuing a new certificate if not already created.
     *
     * @param commonName the desired common name
     * @return the server certificate as a TestPKICertificate
     */
    public TestPKICertificate getOrCreateServerCertificate(@NonNull String commonName) {
        return getOrCreateServerCertificate(commonName, Collections.emptySet());
    }

    /**
     * Get a reference to a {@link TestPKICertificate} for a server certificate with
     * the specified common name (CN=) and subject alternative names (SAN),
     * issuing a new certificate if not already created.
     *
     * @param commonName the desired common name
     * @param subjectAlternativeNames the desired subject alternative names
     * @return the server certificate as a TestPKICertificate
     */
    public TestPKICertificate getOrCreateServerCertificate(@NonNull String commonName, @NonNull Set<String> subjectAlternativeNames) {
        return issuedCertificates.computeIfAbsent(commonName, cn -> new TestPKICertificate(this, commonName, newCertificate(cn, subjectAlternativeNames)));
    }

    /**
     * Get a reference to a {@link TestPKICertificate} for a default client certificate,
     * issuing a new certificate if not already created.
     *
     * @return the default client certificate as a TestPKICertificate
     */
    public TestPKICertificate getOrCreateClientCertificate() {
        return getOrCreateClientCertificate("client");
    }

    /**
     * Get a reference to a {@link TestPKICertificate} for a client certificate with
     * the specified common name (CN=), issuing a new certificate if not already created.
     *
     * @param commonName the desired common name
     * @return the client certificate as a TestPKICertificate
     */
    public TestPKICertificate getOrCreateClientCertificate(@NonNull String commonName) {
        return issuedCertificates.computeIfAbsent(commonName, cn -> new TestPKICertificate(this, commonName, newCertificate(cn, Collections.emptySet())));
    }

    public TestPKICertificate getCertificateBySerialNumber(long serialNumber) {
        if (serialNumber > 0) {
            for (HeldCertificate certificate : caCertificates.values()) {
                if (certificate.certificate().getSerialNumber().longValueExact() == serialNumber) {
                    return new TestPKICertificate(this, getCn(certificate.certificate()), certificate);
                }
            }
            for (TestPKICertificate certificate : issuedCertificates.values()) {
                if (certificate.getSerialNumber() == serialNumber) {
                    return certificate;
                }
            }
        }
        return null;
    }

    SSLSocketFactory getSSLSocketFactory(HeldCertificate certificate) {
        return new HandshakeCertificates.Builder()
                .addTrustedCertificate(rootCertificate.certificate())
                .heldCertificate(certificate, intermediateCertificate.certificate())
                .build()
                .sslSocketFactory();
    }

    X509TrustManager getTrustManager(HeldCertificate certificate) {
        return new HandshakeCertificates.Builder()
                .addTrustedCertificate(rootCertificate.certificate())
                .heldCertificate(certificate, intermediateCertificate.certificate())
                .build()
                .trustManager();
    }

    private HeldCertificate newCertificate(HeldCertificate.Builder builder) {
        switch (keyType) {
            case ECDSA_256:
                builder.ecdsa256();
                break;
            case RSA_2048:
                builder.rsa2048();
                break;
            default:
                throw new RuntimeException("unexpected KeyType: " + keyType.name());
        }
        HeldCertificate certificate = builder.build();
        log.info("issued certificate {}: {}", certificate.certificate().getSerialNumber(), certificate.certificate().getSubjectDN());
        return certificate;
    }

    private HeldCertificate newCertificate(String commonName, Set<String> subjectAlternativeNames) {
        HeldCertificate.Builder builder = new HeldCertificate.Builder()
                .commonName(commonName)
                .organizationalUnit(ORGANIZATIONAL_UNIT)
                .serialNumber(serialNumber.getAndIncrement())
                .signedBy(intermediateCertificate);
        for (String san : subjectAlternativeNames) {
            builder.addSubjectAlternativeName(san);
        }
        return newCertificate(builder);
    }

    @SneakyThrows
    File createKeystoreFile(
            String prefix,
            String password,
            HeldCertificate keyEntryCertificate
    ) {
        File file = newFile(prefix, ".pkcs12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password.toCharArray());
        if (keyEntryCertificate != null) {
            String alias = getCn(keyEntryCertificate.certificate());
            keyStore.setKeyEntry(alias, keyEntryCertificate.keyPair().getPrivate(), password.toCharArray(), new Certificate[]{keyEntryCertificate.certificate()});
        }
        for (Map.Entry<String, HeldCertificate> entry : caCertificates.entrySet()) {
            keyStore.setCertificateEntry(entry.getKey(), entry.getValue().certificate());
        }
        try (FileOutputStream fos = new FileOutputStream(file.getAbsolutePath())) {
            keyStore.store(fos, password.toCharArray());
        }
        log.debug("wrote keystore: {}", file.getAbsolutePath());
        return file;
    }


    @SneakyThrows
    File createPemFile(
            String prefix,
            String suffix,
            Collection<HeldCertificate> certificates,
            Function<HeldCertificate, byte[]> function
    ) {
        File file = newFile(prefix, suffix);
        try (FileOutputStream fos = new FileOutputStream(file.getAbsolutePath())) {
            boolean first = true;
            for (HeldCertificate certificate : certificates) {
                if (first) {
                    first = false;
                } else {
                    fos.write("\n".getBytes());
                }
                fos.write(String.format("# %s%n", certificate.certificate().getSubjectDN().getName()).getBytes());
                fos.write(function.apply(certificate));
            }
        }
        log.debug("wrote PEM file: {}", file.getAbsolutePath());
        return file;
    }

    @SneakyThrows
    private File newFile(String prefix, String suffix) {
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
