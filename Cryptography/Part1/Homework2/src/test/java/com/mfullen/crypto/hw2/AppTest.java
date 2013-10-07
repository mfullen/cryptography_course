/*
 * Copyright PWF Technology LLC
 */
package com.mfullen.crypto.hw2;

import org.junit.Test;
import static org.junit.Assert.*;

import com.mfullen.crypto.common.HexUtils;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import org.junit.Before;

/**
 *
 * @author mfullen
 */
public class AppTest
{
    public static final String INVALID_CHAR = ".";
    private static final String UTF8 = "UTF-8";
    private SecureRandom random = new SecureRandom();
    private static final String AES_COUNTER_NOPADDING = "AES/CTR/NOPADDING";
    private static final String AES_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding";
    private static final Charset ASCII = Charset.forName("US-ASCII");

    @Before
    public void setup()
    {
        this.random = new SecureRandom();
    }

    private IvParameterSpec generateIV(Cipher cipher) throws Exception
    {
        byte[] ivBytes = new byte[cipher.getBlockSize()];
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    private byte[] encrypt(String passphrase, String plaintext, String cipherType)
            throws Exception
    {
        SecretKey key = generateKey(passphrase);

        Cipher cipher = Cipher.getInstance(cipherType);
        cipher.init(Cipher.ENCRYPT_MODE, key, generateIV(cipher), random);
        return cipher.doFinal(plaintext.getBytes());
    }

    private String decrypt(String passphrase, byte[] ciphertext, String cipherType)
            throws
            Exception
    {
        SecretKey key = generateKey(passphrase);

        Cipher cipher = Cipher.getInstance(cipherType);
        cipher.init(Cipher.DECRYPT_MODE, key, generateIV(cipher), random);
        return new String(cipher.doFinal(ciphertext));
    }

    private SecretKey generateKey(String passphrase) throws Exception
    {
        SecureRandom sr1 = SecureRandom.getInstance("SHA1PRNG");
        sr1.setSeed(passphrase.getBytes());
        byte[] k = new byte[128 / 8];
        sr1.nextBytes(k);
        SecretKeySpec encKey = new SecretKeySpec(k, "AES");
        return encKey;
    }

    private SecretKey generateKey2(String passphrase) throws Exception
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(passphrase.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        return new SecretKeySpec(keyBytes, "AES");
    }

    @Test
    public void programming_Question1() throws Exception
    {
        final String algorithm = "AES/CBC/PKCS5Padding";
        final String cbc_key = "140b41b22a29beb4061bda66b6747e14";

        final String iv = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee";
        final String c1 = "2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
        final String cipherText = iv + c1;
        //String string = new String(Hex.decode(cbc_key), UTF8);
//        SecretKey key = generateKey2(cbc_key);
//        Cipher cipher = Cipher.getInstance("AES");
//        byte[] ivBytes = new byte[cipher.getBlockSize()];
//        System.arraycopy(new Base64().decode(cipherText), 0, ivBytes, 0, ivBytes.length);
//        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
//        //cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
//        cipher.init(Cipher.DECRYPT_MODE, key);


        String base64Cipher = "iz1qFlQJfs6Ycp+gcc2z4w==";
        byte[] cipherBytes = cipherText.getBytes();
        //byte[] iv2 = "1234567812345678".getBytes(ASCII);





        //Cipher cipher2 = Cipher.getInstance("AES/CBC/NOPADDING");
        Cipher cipher2 = Cipher.getInstance(AES_CBC_PKCS5Padding);

        byte[] ivBytes = new byte[cipher2.getBlockSize()];
        System.arraycopy(cipherText.getBytes(), 0, ivBytes, 0, ivBytes.length);
        byte[] keyBytes = ivBytes.clone();
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        cipher2.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);

        byte[] result = cipher2.doFinal(cipherBytes);
        System.out.println(new String(result));
//
//        byte[] decodedValue = cipherText.getBytes();
//        byte[] decryptedVal = cipher.doFinal(decodedValue);
//        String clearText = new String(decryptedVal);
//
//        assertEquals("test", clearText);
    }

    @Test
    public void hwSetQuestion8() throws UnsupportedEncodingException
    {
        int aesblockSize = 16; //bytes
        int payloadLength = 128; //bytes
        int payloadLengthWithIV = payloadLength - aesblockSize; //bytes
        int expectedMessageSize = payloadLength - aesblockSize;

        System.out.println("Expected Message Size: " + expectedMessageSize);
        System.out.println("Total Number of blocks: " + (1.0 * payloadLength / aesblockSize));
        String[] answerchoices =
        {
            "The most direct computation would be for the enemy to try all 2^r possible keys, one by one",
            "If qualified opinions incline to believe in the exponential conjecture, then I think we cannot afford not to make use of it",
            "To consider the resistance of an enciphering process to being broken we should assume that at same times the enemy knows everything but the key being used and to break it needs only discover the key from this information",
            "An enciphering-deciphering machine (in general outline) of my invention has been sent to your organization",
            "The significance of this general conjecture, assuming its truth, is easy to see. It means that it may be feasible to design ciphers that are effectively unbreakable",
            "In this letter I make some remarks on a general principle relevant to enciphering in general and my machine"
        };

        System.out.println();
        for (int i = 0; i < answerchoices.length; i++)
        {
            int byteSize = answerchoices[i].getBytes(UTF8).length;
            double blocksFilled = byteSize / 16.0;
            int paddingSize = (payloadLength - byteSize);
            int prePendedSize = (payloadLength + aesblockSize);
            System.out.println("Byte Size: " + byteSize);
            System.out.println("Blocks Filled: " + blocksFilled);
            System.out.println("Padding Size: " + paddingSize);
            System.out.println("Prepended IV size: " + prePendedSize);
            System.out.println();
        }
    }
}