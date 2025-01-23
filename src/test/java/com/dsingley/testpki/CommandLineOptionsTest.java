package com.dsingley.testpki;

import org.junit.jupiter.api.Test;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertAll;

class CommandLineOptionsTest {

    @Test
    void testNoArgs() {
        String[] args = {};
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> CommandLineOptions.parse(args))
                .withMessageContaining("Usage:");
    }

    @Test
    void testOnlyBaseDirectory() {
        String[] args = {"./baseDirectory"};
        CommandLineOptions options = CommandLineOptions.parse(args);
        assertAll(
                () -> assertThat(options.getBaseDirectory()).isEqualTo(new File("./baseDirectory")),
                () -> assertThat(options.getKeyType()).isEqualTo(KeyType.ECDSA_256),
                () -> assertThat(options.isExport()).isFalse(),
                () -> assertThat(options.getVariableNamePrefix()).isNull()
        );
    }

    @Test
    void testKeyType() {
        String[] args = {"./baseDirectory", "--keyType", "RSA_2048"};
        CommandLineOptions options = CommandLineOptions.parse(args);
        assertThat(options.getKeyType()).isEqualTo(KeyType.RSA_2048);
    }

    @Test
    void testMissingKeyType() {
        String[] args = {"./baseDirectory", "--keyType"};
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> CommandLineOptions.parse(args))
                .withMessageContaining("Usage:");
    }

    @Test
    void testInvalidKeyType() {
        String[] args = {"./baseDirectory", "--keyType", "INVALID_KEY_TYPE"};
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> CommandLineOptions.parse(args))
                .withMessageContaining("No enum constant");
    }

    @Test
    void testExport() {
        String[] args = {"./baseDirectory", "--export"};
        CommandLineOptions options = CommandLineOptions.parse(args);
        assertThat(options.isExport()).isTrue();
    }

    @Test
    void testExportWithVariableNamePrefix() {
        String[] args = {"./baseDirectory", "--export", "PREFIX"};
        CommandLineOptions options = CommandLineOptions.parse(args);
        assertAll(
                () -> assertThat(options.isExport()).isTrue(),
                () -> assertThat(options.getVariableNamePrefix()).isEqualTo("PREFIX")
        );
    }

    @Test
    void testExportAndKeyType() {
        String[] args = {"./baseDirectory", "--export", "--keyType", "RSA_2048"};
        CommandLineOptions options = CommandLineOptions.parse(args);
        assertAll(
                () -> assertThat(options.isExport()).isTrue(),
                () -> assertThat(options.getKeyType()).isEqualTo(KeyType.RSA_2048)
        );
    }

    @Test
    void testKeyTypeAndExport() {
        String[] args = {"./baseDirectory", "--keyType", "RSA_2048", "--export"};
        CommandLineOptions options = CommandLineOptions.parse(args);
        assertAll(
                () -> assertThat(options.isExport()).isTrue(),
                () -> assertThat(options.getKeyType()).isEqualTo(KeyType.RSA_2048)
        );
    }

    @Test
    void testExportWithVariableNamePrefixAndKeyType() {
        String[] args = {"./baseDirectory", "--export", "PREFIX", "--keyType", "RSA_2048"};
        CommandLineOptions options = CommandLineOptions.parse(args);
        assertAll(
                () -> assertThat(options.isExport()).isTrue(),
                () -> assertThat(options.getKeyType()).isEqualTo(KeyType.RSA_2048),
                () -> assertThat(options.getVariableNamePrefix()).isEqualTo("PREFIX")
        );
    }

    @Test
    void testKeyTypeAndExportWithVariableNamePrefix() {
        String[] args = {"./baseDirectory", "--keyType", "RSA_2048", "--export", "PREFIX"};
        CommandLineOptions options = CommandLineOptions.parse(args);
        assertAll(
                () -> assertThat(options.isExport()).isTrue(),
                () -> assertThat(options.getKeyType()).isEqualTo(KeyType.RSA_2048),
                () -> assertThat(options.getVariableNamePrefix()).isEqualTo("PREFIX")
        );
    }
}
