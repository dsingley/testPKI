package com.dsingley.testpki;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class TestPKICertificateTest {

    @Test
    void test() {
        TestPKI testPKI = new TestPKI(KeyType.ECDSA_256, null);
        TestPKICertificate certificate = testPKI.getOrCreateServerCertificate();
        assertAll(
                () -> assertThat(certificate.getSubjectDN()).startsWith("CN=server"),
                () -> assertThat(certificate.getSerialNumber()).isGreaterThan(1),
                () -> assertThat(certificate.getCertPem()).startsWith("-----BEGIN CERTIFICATE-----"),
                () -> assertThat(certificate.getKeyPem()).startsWith("-----BEGIN PRIVATE KEY-----")
        );
    }
}
