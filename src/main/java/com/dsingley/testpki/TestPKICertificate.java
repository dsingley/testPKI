package com.dsingley.testpki;

import lombok.Getter;
import lombok.SneakyThrows;
import lombok.Synchronized;
import okhttp3.tls.HeldCertificate;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;

/**
 * A TestPKICertificate represents a certificated issued by a {@link TestPKI} instance.
 * <p>
 * It can create PKCS12 keystore and/or PEM files containing the issued certificate
 * and access to the password for the PKCS12 keystore.
 * <p>
 * It can provide {@link SSLSocketFactory} and {@link X509TrustManager} instances to use
 * for TLS communication.
 */
public class TestPKICertificate {
    private final TestPKI testPKI;
    private final String commonName;
    private final HeldCertificate certificate;
    @Getter(lazy = true) private final String certificateFingerprintSHA256 = computeFingerprint(() -> certificate.certificate().getEncoded(), "SHA-256");
    @Getter(lazy = true) private final String publicKeyFingerprintSHA256 = computeFingerprint(() -> certificate.keyPair().getPublic().getEncoded(), "SHA-256");
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
     * Get the key pair associated with the certificate.
     *
     * @return the private and public keys of the certificate as a KeyPair object
     */
    public KeyPair getKeyPair() {
        return certificate.keyPair();
    }

    /**
     * Get a reference to a keystore file containing the certificate, creating
     * the file on disk if not already created.
     *
     * @return the keystore file as a File object
     */
    @Synchronized
    public File getOrCreateKeystoreFile() {
        if (keystoreFile != null) {
            return keystoreFile;
        }
        keystoreFile = testPKI.createKeystoreFile(commonName, getKeystorePassword(), certificate);
        return keystoreFile;
    }

    /**
     * Get a reference to a PEM file containing the public certificate, creating
     * the file on disk if not already created.
     *
     * @return the certificate PEM file as a File object
     */
    @Synchronized
    public File getOrCreateCertPemFile() {
        if (certPemFile != null) {
            return certPemFile;
        }
        certPemFile = testPKI.createPemFile(commonName, ".cert", Collections.singleton(certificate), c -> c.certificatePem().getBytes());
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
     * the file on disk if not already created.
     *
     * @return the key PEM file as a File object
     */
    @Synchronized
    public File getOrCreateKeyPemFile() {
        if (keyPemFile != null) {
            return keyPemFile;
        }
        keyPemFile = testPKI.createPemFile(commonName, ".key", Collections.singleton(certificate), c -> c.privateKeyPkcs8Pem().getBytes());
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

    @SneakyThrows
    private static String computeFingerprint(ThrowingSupplier<byte[]> encodedValueSupplier, String algorithm) {
        byte[] encoded = encodedValueSupplier.get();
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashed = digest.digest(encoded);
        StringBuilder sb = new StringBuilder();
        for (byte b : hashed) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString().toLowerCase();
    }

    private static String randomPassword() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    @FunctionalInterface
    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }
}
