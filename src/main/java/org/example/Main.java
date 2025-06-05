package org.example;

import org.example.commands.DecryptDirCommand;
import org.example.commands.DecryptFileCommand;
import org.example.commands.EncryptDirCommand;
import org.example.commands.EncryptFileCommand;
import picocli.CommandLine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@CommandLine.Command(name = "crypto-scam", mixinStandardHelpOptions = true, description = "Crypt files and directories", subcommands = {
        EncryptFileCommand.class,
        DecryptFileCommand.class,
        EncryptDirCommand.class,
        DecryptDirCommand.class
})
public class Main implements Runnable {
    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    public static void main(String[] args) {
        int exitCode;
        if (args.length == 0 && System.console() == null) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().equalsIgnoreCase("exit")) break;

                    String[] commandArgs = line.trim().split("\\s+");
                    exitCode = new CommandLine(new Main()).execute(commandArgs);
                }
            } catch (IOException e) {
                System.err.println("Ошибка чтения из stdin: " + e.getMessage());
                System.exit(1);
            }
        } else {
            exitCode = new CommandLine(new Main()).execute(args);
            System.exit(exitCode);
        }
    }
}