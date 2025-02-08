# testPKI

The testPKI project is inspired by and builds upon [OkHttp TLS](https://github.com/square/okhttp/tree/master/okhttp-tls)
to simplify instantiation of test Public Key Infrastructure (PKI) environments.

## Integration Testing

testPKI can be used in integration tests to provide server and client certificates for
tested components and tools like [MockWebServer](https://github.com/square/okhttp/tree/master/mockwebserver).

```java
@Test
void exampleTest() throws Exception {
    TestPKI testPKI = new TestPKI(KeyType.RSA_2048, null);
    
    try (MockWebServer mockWebServer = new MockWebServer()) {
        mockWebServer.useHttps(testPKI.getOrCreateServerCertificate().getSSLSocketFactory());
        mockWebServer.requestClientAuth();

        mockWebServer.enqueue(new MockResponse.Builder()
                .code(200)
                .body("Hello, Test")
                .build()
        );

        TestPKICertificate clientCertificate = testPKI.getOrCreateClientCertificate();
        OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(clientCertificate.getSSLSocketFactory(), clientCertificate.getTrustManager())
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
```

## Command Line

testPKI can be run stand alone to create common PKI artifacts.

Usage:
```
java TestPKI <base directory> [--export [variable name prefix]] [--keyType ECDSA_256|RSA_2048]
```

For example, the following invocation will create eight files in the `/tmp` directory and output 11
environment variables describing the created artifacts and required passwords.

```bash
$ java -jar target/testpki-0.5.0-jar-with-dependencies.jar /tmp --export TESTPKI
```

```bash
export TESTPKI_TRUSTSTORE_PATH=/tmp/truststore.pkcs12
export TESTPKI_TRUSTSTORE_PASSWORD='changeit'
export TESTPKI_CA_PATH=/tmp/ca.pem
export TESTPKI_SERVER_KEYSTORE_PATH=/tmp/server.pkcs12
export TESTPKI_SERVER_KEYSTORE_PASSWORD='fNrAYNElDXVIGEqMfr6lsDx9nXM='
export TESTPKI_SERVER_CERT_PATH=/tmp/server.cert
export TESTPKI_SERVER_KEY_PATH=/tmp/server.key
export TESTPKI_CLIENT_KEYSTORE_PATH=/tmp/client.pkcs12
export TESTPKI_CLIENT_KEYSTORE_PASSWORD='QovMjwazrBr2JjJOwxLssTTiEd0='
export TESTPKI_CLIENT_CERT_PATH=/tmp/client.cert
export TESTPKI_CLIENT_KEY_PATH=/tmp/client.key
```
