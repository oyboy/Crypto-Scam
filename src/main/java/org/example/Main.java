package org.example;

import org.example.commands.DecryptDirCommand;
import org.example.commands.DecryptFileCommand;
import org.example.commands.EncryptDirCommand;
import org.example.commands.EncryptFileCommand;
import picocli.CommandLine;
import java.util.Scanner;

@CommandLine.Command(name = "crypto-scam", description = "Crypt files and directories", subcommands = {
        EncryptFileCommand.class,
        DecryptFileCommand.class,
        EncryptDirCommand.class,
        DecryptDirCommand.class
})
public class Main implements Runnable {
    @Override
    public void run() {
        new CommandLine(this).usage(System.out);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("> ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Выход из программы.");
                break;
            }

            String[] commandArgs = input.split(" ");
            new CommandLine(new Main()).execute(commandArgs);
        }
        scanner.close();
    }
}