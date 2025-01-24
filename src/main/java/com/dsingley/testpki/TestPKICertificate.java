package com.dsingley.testpki;

import lombok.Getter;
import lombok.Synchronized;
import org.checkerframework.checker.nullness.qual.Nullable;
import okhttp3.tls.HeldCertificate;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;

/**
 * A TestPKICertificate represents a certificated issued by a {@link TestPKI} instance.
 * <p>
 * It can create persistent or temporary PKCS12 keystore and/or PEM files containing
 * the issued certificate and access to the password for the PKCS12 keystore.
 * <p>
 * It can provide {@link SSLSocketFactory} and {@link X509TrustManager} instances to use
 * for TLS communication.
 */
public class TestPKICertificate {
    private final TestPKI testPKI;
    private final String commonName;
    private final HeldCertificate certificate;
    @Getter(lazy = true) private final String keystorePassword = randomPassword();
    private File keystoreFile;
    private File certPemFile;
    private File keyPemFile;

    TestPKICertificate(TestPKI testPKI, String commonName, HeldCertificate certificate) {
        this.testPKI = testPKI;
        this.commonName = commonName;
        this.certificate = certificate;
    }

    /**
     * Get the distinguished name (DN) of the subject of the certificate.
     *
     * @return the subject DN as a string
     */
    public String getSubjectDN() {
        return certificate.certificate().getSubjectDN().getName();
    }

    /**
     * Get the serial number of the certificate.
     *
     * @return the serial number of the certificate as a long
     */
    public long getSerialNumber() {
        return certificate.certificate().getSerialNumber().longValueExact();
    }

    /**
     * Get a reference to a keystore file containing the certificate, creating
     * a temporary file on disk if not already created.
     *
     * @return the keystore file as a File object
     */
    public File getKeystoreFile() {
        return getKeystoreFile(null);
    }

    /**
     * Get a reference to a keystore file containing the certificate, creating
     * the file on disk in the specified directory if not already created.
     *
     * @param baseDirectory the directory in which to create the file, will create a temporary file if null
     * @return the keystore file as a File object
     */
    @Synchronized
    public File getKeystoreFile(@Nullable File baseDirectory) {
        if (keystoreFile != null) {
            return keystoreFile;
        }
        keystoreFile = testPKI.createKeystoreFile(baseDirectory, commonName, getKeystorePassword(), certificate);
        return keystoreFile;
    }

    /**
     * Get a reference to a PEM file containing the public certificate, creating
     * a temporary file on disk if not already created.
     *
     * @return the certificate PEM file as a File object
     */
    public File getCertPemFile() {
        return getCertPemFile(null);
    }

    /**
     * Get a reference to a PEM file containing the public certificate, creating
     * the file on disk in the specified directory if not already created.
     *
     * @return the certificate PEM file as a File object
     */
    @Synchronized
    public File getCertPemFile(@Nullable File baseDirectory) {
        if (certPemFile != null) {
            return certPemFile;
        }
        certPemFile = TestPKI.createPemFile(baseDirectory, commonName, ".cert", Collections.singleton(certificate), c -> c.certificatePem().getBytes());
        return certPemFile;
    }

    /**
     * Get the certificate in PEM format.
     *
     * @return the certificate as a PEM-encoded string
     */
    public String getCertPem() {
        return certificate.certificatePem();
    }

    /**
     * Get a reference to a PEM file containing the unencrypted private key, creating
     * a temporary file on disk if not already created.
     *
     * @return the key PEM file as a File object
     */
    public File getKeyPemFile() {
        return getKeyPemFile(null);
    }

    /**
     * Get a reference to a PEM file containing the unencrypted private key, creating
     * the file on disk in the specified directory if not already created.
     *
     * @return the key PEM file as a File object
     */
    @Synchronized
    public File getKeyPemFile(@Nullable File baseDirectory) {
        if (keyPemFile != null) {
            return keyPemFile;
        }
        keyPemFile = TestPKI.createPemFile(baseDirectory, commonName, ".key", Collections.singleton(certificate), c -> c.privateKeyPkcs8Pem().getBytes());
        return keyPemFile;
    }

    /**
     * Get the unencrypted private key in PKCS#8 PEM format.
     *
     * @return the private key as a PEM-encoded string
     */
    public String getKeyPem() {
        return certificate.privateKeyPkcs8Pem();
    }

    /**
     * Get an SSLSocketFactory that is configured with the certificate
     * and the certificate authorities of the issuing TestPKI instance.
     *
     * @return an SSLSocketFactory instance
     */
    public SSLSocketFactory getSSLSocketFactory() {
        return testPKI.getSSLSocketFactory(certificate);
    }

    /**
     * Get an X509TrustManager that is configured with the certificate
     * and the certificate authorities of the issuing TestPKI instance.
     *
     * @return an SSLSocketFactory instance
     */
    public X509TrustManager getTrustManager() {
        return testPKI.getTrustManager(certificate);
    }

    private static String randomPassword() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}
