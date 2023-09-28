import java.util.Scanner;

public class SimpleSec {
    public static void main(String[] args) throws Exception {
        recogerArgumentos(args);
    }

    public static void recogerArgumentos(String[] args) {
        if (args.length >= 1 & args.length <= 3) {
            if (args[0].equals("g") | args[0].equals("e") | args[0].equals("d")) {
                if (args[0].equals("g")) {
                    genRSAFunc();
                } else if (args[0].equals("e")) {
                    if (args.length == 3) {
                        encryptFileFunc();
                    } else {
                        printError(0);
                    }
                } else {
                    if (args.length == 3) {
                        decryptFileFunc();
                    } else {
                        printError(1);
                    }
                }
            } else {
                printError(2);
            }
        } else {
            printError(3);
        }
    }

    public static void genRSAFunc() {
        System.out.println("Generate a pair of RSA keys.");
        System.out.println("Introduce a passphrase to encrypt the private key:");
        Scanner scanner = new Scanner(System.in);
        String passphrase = scanner.nextLine();
    }

    public static void encryptFileFunc() {
        System.out.println("Encrypt and sign the file.");
        System.out.println("Introduce a passphrase to encrypt the private key:");
        Scanner scanner = new Scanner(System.in);
        String passphrase = scanner.nextLine();
    }

    public static void decryptFileFunc() {
        System.out.println("Decrypt the file.");
        System.out.println("Introduce a passphrase to encrypt the private key:");
        Scanner scanner = new Scanner(System.in);
        String passphrase = scanner.nextLine();
    }

    public static void printError(int err) {
        System.out.printf("Error: ");
        if (err == 0 | err == 1) {
            System.out.println("Introduce the source file path and the destination file.");
            if (err == 0) {
                System.out.println("Format: java SimpleSec <e> <sourceFile> <destinationFile>");
            } else {
                System.out.println("Format: java SimpleSec <d> <sourceFile> <destinationFile>");
            }  
        } else if (err == 2) {
            System.out.println("First argument should be: g/e/d");
        } else {
            System.out.println("The format should be: java SimpleSec <command> [sourceFile] [destinationFile]");
        }
    }
}
