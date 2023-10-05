import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SimpleSec {
    public static void main(String[] args) throws Exception {
        try {
            argumentParser(args);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    /*************************************************************************************/
    /* Method to parse arguments */
    /*************************************************************************************/
    public static void argumentParser(String[] args) throws Exception {
        if (args.length >= 1 & args.length <= 3) {
            switch (args[0]) {
                case "g":
                    if (args.length != 1) throw new InvalidParametersException("Too many arguments. Format is: java SimpleSec g"); 
                    genRSAFunc();
                    break;
                case "e":
                    if (args.length != 3) throw new InvalidParametersException("Introduce the source file path and the destination file.");
                    encryptFileFunc(args[1], args[2]);
                    break;
                case "d":
                    if (args.length != 3) throw new InvalidParametersException("Introduce the source file path and the destination file.");
                    decryptFileFunc(args[1], args[2]);
                    break;
                default:
                    throw new InvalidParametersException("The format should be: java SimpleSec <g|e|d> [sourceFile] [destinationFile]");
            }
        } else {
            throw new InvalidParametersException("The format should be: java SimpleSec <g|e|d> [sourceFile] [destinationFile]");
        }
    }

    /*************************************************************************************/
    /* Method to generate RSA keys */
    /*************************************************************************************/
    public static void genRSAFunc() throws Exception {
        RSALibrary rsa = new RSALibrary();

        // Get passphrase from the user
        System.out.println("Introduce a passphrase to encrypt the private key:");
        Scanner scanner = new Scanner(System.in);
        String passphrase = scanner.nextLine();

        // Check valid passphrase
        while (passphrase.length() != 16) {
            if (passphrase.length() > 16) {
                System.out.println("Passphrase too long. It must be 16 characters long.");
            } else {
                System.out.println("Passphrase too short. It must be 16 characters long.");
            }
            System.out.println("Introduce a passphrase to encrypt the private key:");
            passphrase = scanner.nextLine();
        }

        // Generate RSA keys
        rsa.generateKeys(passphrase.getBytes());
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
            byte [] cipherKey = rsa.encrypt(AESKey, publicKey);
            System.out.print("AESkey: ");
            printBytesInHex(cipherKey);
            System.out.println("len: " + cipherKey.length);

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

    public static void decryptFileFunc(String sourceFile, String destFile) throws Exception {

        SymmetricCipher s = new SymmetricCipher();
        RSALibrary rsa = new RSALibrary();

        PrivateKey privateKey = getPrivateKey();
        PublicKey publicKey = getPublicKey();

        byte [] sign = new byte[128];
        byte[] filesBytes;
        byte[] AESKeyCipher = new byte[128];
        byte[] AESKey = new byte[16];
        
        try {
            filesBytes = Files.readAllBytes(Path.of(sourceFile));
            byte[] packet = new byte[filesBytes.length - 128];
            byte[] ciphertext = new byte[packet.length - 128];
            byte[] plaintext = new byte[packet.length - 128];
            System.arraycopy(filesBytes, filesBytes.length - 128, sign, 0, sign.length);
            System.arraycopy(filesBytes, 0, packet, 0, filesBytes.length - 128);
            if (!rsa.verify(packet, sign, publicKey)) {
                System.out.println("Error. The verification is not working.");
            }
            System.arraycopy(packet, packet.length - 128, AESKeyCipher, 0, AESKeyCipher.length);
            AESKey = rsa.decrypt(AESKeyCipher, privateKey);
            System.out.print("AESkey: ");
            printBytesInHex(AESKey);
            System.out.println("len: " + AESKey.length);
            System.arraycopy(packet, 0, ciphertext, 0, ciphertext.length);
            plaintext = s.decryptCBC(ciphertext, AESKey);

            Files.write(Path.of(destFile), plaintext);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
     
    }

    private static byte [] randomKeyGenerator() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return (randomBytes);
    }

    private static PrivateKey getPrivateKey() throws Exception{

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
        } catch (InvalidKeyException e) {
            throw new WrongPassphraseException("Password is not correct.");
        } catch (Exception e) {
            throw e;
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

    /*************************************************************************************/
        /* Method to print bytes in hex */
    /*************************************************************************************/
    public static void printBytesInHex(byte[] byteArray) {
        for (byte b : byteArray) {
            System.out.printf("%02X", b);
        }
        System.out.println();
    }
}
