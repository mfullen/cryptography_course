/*
 * Copyright PWF Technology LLC
 */
package com.mfullen.crypto.hw2;

import org.junit.Test;
import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
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



        SecretKey key = generateKey(new String(new Base64().decode(cbc_key), UTF8));
        Cipher cipher = Cipher.getInstance("AES");
        byte[] ivBytes = new byte[cipher.getBlockSize()];
        System.arraycopy(new Base64().decode(cipherText), 0, ivBytes, 0, ivBytes.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        //cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decodedValue = new Base64().decode(cipherText);
        byte[] decryptedVal = cipher.doFinal(decodedValue);
        String clearText = new String(decryptedVal);

        assertEquals("test", clearText);
    }
}