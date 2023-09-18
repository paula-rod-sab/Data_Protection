import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Test {
    public static void main(String[] args) throws Exception {

        // byte[] input = Files.readAllBytes(Paths.get("src/test0.txt"));

        byte[] input = new byte[] {(byte)49, (byte)50, (byte)51};

        System.out.print("Input: ");
        printBytesInHex(input);
        System.out.print("input ASCII: ");
        printBytesInAscii(input);
        System.out.print("input decimal: ");
        printBytesInDecimal(input);

        byte[] bytekey = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
            (byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
            (byte)53, (byte)54};
        System.out.print("Key: ");
        printBytesInHex(bytekey);

        byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
            (byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
            (byte)53, (byte)54};
        System.out.print("IV: ");
        printBytesInHex(iv);

        SymmetricCipher s = new SymmetricCipher();

        byte [] ciphertext = s.encryptCBC(input, bytekey);
        System.out.print("Encriptado: ");
        printBytesInHex(ciphertext);
        // printBytesInAscii(ciphertext);

        byte [] plaintext = s.decryptCBC(ciphertext, bytekey);
        System.out.print("Desencriptado ASCII: ");
        printBytesInAscii(plaintext);
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

    /*************************************************************************************/
	/* Method to print bytes in ASCII */
    /*************************************************************************************/
    public static void printBytesInAscii(byte[] byteArray) {
        for (byte b : byteArray) {
            System.out.print((char) b);
        }
        System.out.println();
    }

    /*************************************************************************************/
	/* Method to print bytes in decimal */
    /*************************************************************************************/
    public static void printBytesInDecimal(byte[] byteArray) {
        for (byte b : byteArray) {
            int decimalValue = b & 0xFF;
            System.out.print(decimalValue + " ");
        }
        System.out.println();
    }
}
