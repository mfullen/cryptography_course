package com.mfullen.homework1;

import java.io.IOException;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author mfullen
 */
public class StringXORer
{
    public String encode(String s, String key)
    {
        return base64Encode(xorWithKey(s.getBytes(), key.getBytes()));
    }

    public String decode(String s, String key)
    {
        return new String(xorWithKey(base64Decode(s), key.getBytes()));
    }

    public byte[] xorWithKey(byte[] a, byte[] key)
    {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++)
        {
            out[i] = (byte) (a[i] ^ key[i % key.length]);
        }
        return out;
    }

    public byte[] base64Decode(String s)
    {
        try
        {
            BASE64Decoder d = new BASE64Decoder();
            return d.decodeBuffer(s);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    public String base64Encode(byte[] bytes)
    {
        BASE64Encoder enc = new BASE64Encoder();
        return enc.encode(bytes).replaceAll("\\s", "");
    }
}
