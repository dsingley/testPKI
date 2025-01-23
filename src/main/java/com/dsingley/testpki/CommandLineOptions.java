package com.dsingley.testpki;

import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.util.Arrays;
import java.util.stream.Collectors;

@Getter
@Builder
class CommandLineOptions {
    private File baseDirectory;
    @Builder.Default private KeyType keyType = KeyType.ECDSA_256;
    private boolean export;
    private String variableNamePrefix;

    static CommandLineOptions parse(String[] args) {
        if (args.length < 1) {
            throw new IllegalArgumentException(usage());
        }
        CommandLineOptions.CommandLineOptionsBuilder builder = CommandLineOptions.builder();
        builder.baseDirectory(new File(args[0]));

        int i = 1;
        while (i < args.length) {
            switch (args[i++]) {
                case "--export":
                    builder.export(true);
                    if (i < args.length && !args[i].startsWith("--")) {
                        builder.variableNamePrefix(args[i++]);
                    }
                    break;
                case "--keyType":
                    if (i < args.length) {
                        builder.keyType(KeyType.valueOf(args[i++]));
                    } else {
                        throw new IllegalArgumentException(usage());
                    }
                    break;
                default:
                    throw new IllegalArgumentException(usage());
            }
        }

        return builder.build();
    }

    private static String usage() {
        String keyTypes = Arrays.stream(KeyType.values())
                .map(Enum::name)
                .collect(Collectors.joining("|"));
        return String.format("Usage: java %s <base directory> [--export [variable name prefix]] [--keyType %s]", TestPKI.class.getName(), keyTypes);
    }
}
