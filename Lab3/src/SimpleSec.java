import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
                        encryptFileFunc(args[1], args[2]);
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
        RSALibrary rsa = new RSALibrary();

        System.out.println("Introduce a passphrase to encrypt the private key:");
        Scanner scanner = new Scanner(System.in);
        String passphrase = scanner.nextLine();
        while (passphrase.length() != 16) {
            if (passphrase.length() > 16) {
                System.out.println("Passphrase too long. It must be 16 characters long.");
            } else {
                System.out.println("Passphrase too short. It must be 16 characters long.");
            }
            System.out.println("Introduce a passphrase to encrypt the private key:");
            passphrase = scanner.nextLine();
        }

        try {
            rsa.generateKeys(passphrase.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void encryptFileFunc(String sourceFile, String destFile) {
        // TO DO: si no hay claves rsa, lanza excepcion -- RSALibrary encrypt
        // TO DO: si mete mal la contraseña al crear el objeto PrivateKey da error
        SymmetricCipher s = new SymmetricCipher();
        RSALibrary rsa = new RSALibrary();
        byte [] AESKey = randomKeyGenerator();

        try {
            PrivateKey privateKey = getPrivateKey();
            PublicKey publicKey = getPublicKey();
            
            byte [] fileBytes = Files.readAllBytes(Path.of(sourceFile));
            byte [] ciphertext = s.encryptCBC(fileBytes, AESKey);
            byte [] cipherKey = rsa.encrypt(ciphertext, publicKey);

            // Concat ciphertext and cipherKey    
            byte[] packet = new byte[ciphertext.length + cipherKey.length];
            System.arraycopy(ciphertext, 0, packet, 0, ciphertext.length);
            System.arraycopy(cipherKey, 0, packet, ciphertext.length, cipherKey.length);

            // Sign the concat packet
            byte [] sign = rsa.sign(packet, privateKey);
            byte[] signedPacket = new byte[packet.length + sign.length];
            System.out.println("Len:" + sign.length);
            System.arraycopy(packet, 0, signedPacket, 0, packet.length);
            System.arraycopy(sign, 0, signedPacket, packet.length, sign.length);

            Files.write(Path.of(destFile), signedPacket);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void decryptFileFunc(String sourceFile, String destFile) {

        SymmetricCipher s = new SymmetricCipher();
        RSALibrary rsa = new RSALibrary();

        PrivateKey privateKey = getPrivateKey();
        PublicKey publicKey = getPublicKey();

        byte [] sign = new byte[128];
        byte[] filesBytes;
        
        try {
            filesBytes = Files.readAllBytes(Path.of(sourceFile));
            byte[] packet = new byte[filesBytes.length - 128];
            System.arraycopy(filesBytes, filesBytes.length - 128, sign, 0, sign.length);
            System.arraycopy(filesBytes, 0, packet, 0, filesBytes.length - 128);
            if (!rsa.verify(packet, sign, publicKey)) {
                System.out.println("Error. The ");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
     
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

    private static byte [] randomKeyGenerator() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return (randomBytes);
    }

    private static PrivateKey getPrivateKey() {

        SymmetricCipher s = new SymmetricCipher();
        Scanner scanner = new Scanner(System.in);
        System.out.println("Introduce your passphrase:");
        String passphrase = scanner.nextLine();
        byte[] bytesPriv;
        PrivateKey privateKey = null;
        try {
            bytesPriv = Files.readAllBytes(Paths.get("./private.key"));
            byte [] privateKeyBytes = s.decryptCBC(bytesPriv, passphrase.getBytes());
            PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
            privateKey = keyfactory2.generatePrivate(keyspec2);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;

    }

    private static PublicKey getPublicKey() {

        RSALibrary rsa = new RSALibrary();

        byte[] bytesPub;
        PublicKey publicKey = null;
        try {
            bytesPub = Files.readAllBytes(Paths.get("./public.key"));
            X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytesPub);
            KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            publicKey = keyfactory.generatePublic(keyspec);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return publicKey;
    }
}
