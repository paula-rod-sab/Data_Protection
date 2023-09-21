import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Test {
    public static void main(String[] args) throws Exception {
        
        RSALibrary r = new RSALibrary();
        r.generateKeys();

        /* Read public key */
        Path path = Paths.get("./public.key");
        byte[] bytes = Files.readAllBytes(path);
        // Public key is stored in x509 format
        X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
        KeyFactory keyfactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyfactory.generatePublic(keyspec);
        // System.out.println("public:" +publicKey.toString());

        /* Read private key */
        path = Paths.get("./private.key");
        byte[] bytes2 = Files.readAllBytes(path);
        // Private key is stored in PKCS8 format
        PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(bytes2);
        KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);
        // System.out.println("private:" + privateKey.toString());

        byte[] plaintext = new byte[] { (byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54,
                (byte) 55, (byte) 56, (byte) 57, (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52,
                (byte) 53, (byte) 54 };

        System.out.println("Sin encriptar: ");
        printBytesInAscii(plaintext);
        byte[] plaintextEnc = r.encrypt(plaintext, publicKey);
        System.out.println("encriptado : ");
        printBytesInAscii(plaintextEnc);
        byte[] plaintextDesc = r.decrypt(plaintextEnc, privateKey);
        System.out.println("Desencriptado : ");
        printBytesInAscii(plaintextDesc);

        byte[] signedInfo = r.sign(plaintext, privateKey);
        System.out.println("signedinfo: ");
        printBytesInAscii(signedInfo);
        boolean result = r.verify(plaintext, signedInfo, publicKey);
        System.out.println("Resultado: " + result);

    }

    /*************************************************************************************/
    /* Method to print bytes in ASCII */
    /*************************************************************************************/
    public static void printBytesInAscii(byte[] byteArray) {
        for (byte b : byteArray) {
            System.out.print((char) b);
        }
        System.out.println();
    }
}
