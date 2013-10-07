package com.mfullen.crypto.common;

import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author mfullen
 */
public class HexUtils
{
    private static final String UTF8 = "UTF-8";
    public static final String INVALID_CHAR = ".";

    public static String xorHex(String a, String b)
    {
        int length = a.length() > b.length() ? b.length() : a.length();
        char[] chars = new char[length];
        for (int i = 0; i < chars.length; i++)
        {
            chars[i] = toHex(fromHex(a.charAt(i)) ^ fromHex(b.charAt(i)));
        }
        return new String(chars);
    }

    public static int fromHex(char c)
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F')
        {
            return c - 'A' + 10;
        }
        if (c >= 'a' && c <= 'f')
        {
            return c - 'a' + 10;
        }
        throw new IllegalArgumentException();
    }

    public static char toHex(int nybble)
    {
        if (nybble < 0 || nybble > 15)
        {
            throw new IllegalArgumentException();
        }
        return "0123456789ABCDEF".toLowerCase().charAt(nybble);
    }

    public static String hexToAscii(String hex)
    {
        try
        {
            byte[] decodeHex = Hex.decodeHex(hex.toCharArray());
            String string = new String(decodeHex, UTF8);
            return string;
            //return filterAscii(string);
        }
        catch (Exception e)
        {
            //System.out.println("Error, returning : ");
            //e.printStackTrace();
            int x = 0;
        }
        return INVALID_CHAR;
    }
}
