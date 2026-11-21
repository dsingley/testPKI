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
                () -> assertThat(certificate.getIssuerDN()).startsWith("CN=Intermediate CA"),
                () -> assertThat(certificate.getSubjectDN()).startsWith("CN=server"),
                () -> assertThat(certificate.getSerialNumber()).isGreaterThan(2),
                () -> assertThat(certificate.getX509Certificate().getSubjectX500Principal().getName()).isEqualTo(certificate.getSubjectDN()),
                () -> assertThat(certificate.getX509Certificate().getSerialNumber().longValueExact()).isEqualTo(certificate.getSerialNumber()),
                () -> assertThat(certificate.getCertificateFingerprintSHA256()).matches("[0-9a-f]{64}"),
                () -> assertThat(certificate.getPublicKeyFingerprintSHA256()).matches("[0-9a-f]{64}"),
                () -> assertThat(certificate.getCertPem()).startsWith("-----BEGIN CERTIFICATE-----"),
                () -> assertThat(certificate.getKeyPem()).startsWith("-----BEGIN PRIVATE KEY-----")
        );
    }

    @Test
    void testDefaultOrganizationalUnit() {
        TestPKI testPKI = new TestPKI(KeyType.ECDSA_256, null, null);
        TestPKICertificate certificate = testPKI.getOrCreateClientCertificate();
        assertAll(
                () -> assertThat(certificate.getIssuerDN()).isEqualTo("CN=Intermediate CA,OU=TestPKI"),
                () -> assertThat(certificate.getSubjectDN()).isEqualTo("CN=client,OU=TestPKI")
        );
    }

    @Test
    void testCustomOrganizationalUnit() {
        TestPKI testPKI = new TestPKI(KeyType.ECDSA_256, null, "My Unit");
        TestPKICertificate certificate = testPKI.getOrCreateClientCertificate();
        TestPKICertificate root = testPKI.getCertificateBySerialNumber(1);
        assertAll(
                () -> assertThat(root.getSubjectDN()).isEqualTo("CN=Root CA,OU=My Unit"),
                () -> assertThat(certificate.getIssuerDN()).isEqualTo("CN=Intermediate CA,OU=My Unit"),
                () -> assertThat(certificate.getSubjectDN()).isEqualTo("CN=client,OU=My Unit")
        );
    }
}
