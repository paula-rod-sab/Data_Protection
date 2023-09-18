import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.*;
import java.security.InvalidKeyException;

public class SymmetricCipher {

	SymmetricEncryption s;
	SymmetricEncryption d;
    final int AES_BLOCK_SIZE = 16;
	
	// Initialization Vector (fixed)
    byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
		(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
		(byte)53, (byte)54};

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
		
        s = new SymmetricEncryption(byteKey);
        
        // Generate the plaintext with padding
		byte[] plaintext = addPadding(input);
        byte[] finalCiphertext = new byte[plaintext.length];

        // Get first block
        byte[] firstBlock = new byte[AES_BLOCK_SIZE];
        System.arraycopy(plaintext, 0, firstBlock, 0, AES_BLOCK_SIZE);
        
        // Generate the ciphertext
        byte[] ciphertext = encryptBlockCBC(iv, firstBlock);
        System.arraycopy(ciphertext, 0, finalCiphertext, 0, AES_BLOCK_SIZE);
 
        for (int i = 1; i < plaintext.length / AES_BLOCK_SIZE; i++) {
            byte[] currentBlock = new byte[AES_BLOCK_SIZE];
            System.arraycopy(plaintext, i * AES_BLOCK_SIZE, currentBlock, 0, AES_BLOCK_SIZE);
            ciphertext = encryptBlockCBC(ciphertext, currentBlock);
            System.arraycopy(ciphertext, 0, finalCiphertext, i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        }
				
		return finalCiphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
	    
        d = new SymmetricEncryption(byteKey);
		byte [] plaintext = new byte[input.length]; 

        // Get first block
        byte[] previousBlock = new byte[AES_BLOCK_SIZE];
        System.arraycopy(input, 0, previousBlock, 0, AES_BLOCK_SIZE);
        byte[] plaintextN = decryptBlockCBC(iv, previousBlock);
        System.arraycopy(plaintextN, 0, plaintext, 0, AES_BLOCK_SIZE);
        
        // Generate the plaintext
        for (int i = 1; i < input.length / AES_BLOCK_SIZE; i++) {
            byte [] currentBlock = new byte[AES_BLOCK_SIZE];
            System.arraycopy(input, i * AES_BLOCK_SIZE, currentBlock, 0, AES_BLOCK_SIZE);
            plaintextN = decryptBlockCBC(previousBlock, currentBlock);
            System.arraycopy(plaintextN, 0, plaintext, i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            previousBlock = currentBlock;
        }

        // Eliminate the padding
        int finalLen = plaintext.length - plaintext[plaintext.length - 1];
        byte [] finalplaintext = new byte[finalLen]; 
        System.arraycopy(plaintext, 0, finalplaintext, 0, finalLen);

		return finalplaintext;
	}

    /*************************************************************************************/
	/* Method to encrypt one block */
    /*************************************************************************************/
    private byte[] encryptBlockCBC (byte[] iv, byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException {
        byte[] vector = XORArray(iv, plaintext);
        byte[] ciphertext = s.encryptBlock(vector);

        return ciphertext;
    }

    /*************************************************************************************/
	/* Method to decrypt one block */
    /*************************************************************************************/
    private byte[] decryptBlockCBC (byte[] iv, byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
        byte[] vector = d.decryptBlock(ciphertext);
        byte[] plaintext = XORArray(vector, iv);

        return plaintext;
    }

    /*************************************************************************************/
	/* Method to add padding */
    /*************************************************************************************/
    private byte[] addPadding (byte[] originalText) {
        byte[] plaintext;
        byte[] padding;

        // Generate padding
        int offset = originalText.length % AES_BLOCK_SIZE;
        if (offset != 0) {
            int paddingSize = AES_BLOCK_SIZE - offset;
            padding = new byte[paddingSize];
            Arrays.fill(padding, (byte)paddingSize);
            plaintext = new byte[originalText.length + padding.length];
        } else {
            padding = new byte[AES_BLOCK_SIZE];
            Arrays.fill(padding, (byte) AES_BLOCK_SIZE);
            plaintext = new byte[originalText.length + AES_BLOCK_SIZE];
        }

        // Concact padding to original text
		System.arraycopy(originalText, 0, plaintext, 0, originalText.length);
        System.arraycopy(padding, 0, plaintext, originalText.length, padding.length);

        return plaintext;
    }

    /*************************************************************************************/
	/* Method to XOR two sequences */
    /*************************************************************************************/
    private byte[] XORArray(byte[] seq1, byte[] seq2){
        byte[] resultado = new byte[seq1.length];

        for (int i = 0; i < seq1.length; i++) {
            resultado[i] = (byte) (seq1[i] ^ seq2[i]);
        }

        return resultado;
    }

}
