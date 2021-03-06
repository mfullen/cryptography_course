package com.mfullen.homework1;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author mfullen
 */
public class AppTest
{
    public static final String INVALID_CHAR = ".";
    private String[] cipherTexts;
    private String targetCipher;
    private static final String UTF8 = "UTF-8";

    @Before
    public void setUp()
    {
        this.targetCipher = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904";
        String[] texts =
        {
            "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
            "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
            "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
            "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
            "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
            "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
            "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
            "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
            "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
            "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"
        };

        this.cipherTexts = texts;

    }

    public String toHex(String arg)
    {
        try
        {
            return String.format("%02x", new BigInteger(1, arg.getBytes(UTF8)));
        }
        catch (UnsupportedEncodingException ex)
        {
            Logger.getLogger(AppTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Xors 2 hex strings
     *
     * @param x
     * @param y
     * @return
     */
    public String xor(String x, String y)
    {
        String xor = null;
        try
        {
            BigInteger x1 = new BigInteger(x, 16);
            BigInteger y1 = new BigInteger(y, 16);
            BigInteger bigIntegerXor = x1.xor(y1);
            xor = Hex.encodeHexString(bigIntegerXor.toByteArray());
        }
        catch (Exception e)
        {
        }
        return xor;
    }

    public String xor2(String x, String y)
    {
        String xor = null;
        try
        {
            BigInteger x1 = new BigInteger(x, 16);
            BigInteger y1 = new BigInteger(y, 16);
            BigInteger bigIntegerXor = x1.xor(y1);
            xor = Hex.encodeHexString(bigIntegerXor.toByteArray());
            xor = bigIntegerXor.toString(16);
        }
        catch (Exception e)
        {
        }
        return xor;
    }

    public String xorHex(String a, String b)
    {
        int length = a.length() > b.length() ? b.length() : a.length();
        char[] chars = new char[length];
        for (int i = 0; i < chars.length; i++)
        {
            chars[i] = toHex(fromHex(a.charAt(i)) ^ fromHex(b.charAt(i)));
        }
        return new String(chars);
    }

    private static int fromHex(char c)
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

    private char toHex(int nybble)
    {
        if (nybble < 0 || nybble > 15)
        {
            throw new IllegalArgumentException();
        }
        return "0123456789ABCDEF".toLowerCase().charAt(nybble);
    }

    public boolean isValidAscii(char c)
    {
        if (c > 122)
        {
            return false;
        }
        if (c < 32 && c != 10)
        {
            return false;
        }

        if (c > 32 && c < 48)
        {
            return false;
        }


        return true;
    }

    public String filterAscii(String string)
    {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < string.length(); i++)
        {

            char c = string.charAt(i);

            if (isValidAscii(c))
            {
                output.append(c);
            }
            else
            {
                output.append(INVALID_CHAR);
            }

        }
        return output.toString();
    }

    public String hexToAscii(String hex)
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

    public String hexStringXor(String a, String b)
    {
        String result = "";

        int length = Math.min(a.length(), b.length());

        for (int i = 0; i < length; i = i + 2)
        {
            String aHex = a.substring(i, i + 1);
            String bHex = b.substring(i, i + 1);
            BigInteger aInt = new BigInteger(aHex, 16);
            BigInteger bInt = new BigInteger(bHex, 16);
            //int aInt = Integer.parseInt(aHex, 16);
            //int bInt = Integer.parseInt(bHex, 16);
            int xor = aInt.intValue() ^ bInt.intValue();
            //result += Integer.toHexString(xor);
            result += (char) xor;
        }

        return result;
    }

    /**
     * Test of main method, of class App.
     */
    @Test
    public void testHelperMethods()
    {
        final String crib = "the";
        String cribHex = toHex(crib);

        String c1 = "3b101c091d53320c000910";
        String c2 = "071d154502010a04000419";
        String xor = xorHex(c1, c2);

        assertEquals("746865", cribHex);
        assertEquals("3c0d094c1f523808000d09", xor);

        String xor1 = xorHex(xor, cribHex);
        assertEquals("48656c", xor1);
        assertEquals("Hel", hexToAscii(xor1));


        assertEquals("48656c6c6f", toHex("Hello"));
        String xor2 = xorHex("3c0d094c1f", toHex("Hello"));
        assertEquals("the p", hexToAscii(xor2));
//        {
//            String xor3 = xor("c0d094c1f5", toHex("Hello"));
//            assertEquals("the p", hexToAscii(xor3));
//        }
//        {
//            String xor3 = xor("0d094c1f52", toHex("Hello"));
//            assertEquals("the p", hexToAscii(xor3));
//        }
//        {
//            String xor3 = xor("523808000d", toHex("Hello"));
//            assertEquals("the p", hexToAscii(xor3));
//        }
        {
            String xor3 = xor(xor, toHex("the program"));
            assertEquals("Hello World", hexToAscii(xor3));
        }

    }

    @Test
    public void testHelperMethods2()
    {
        final String crib = "the";
        String cribHex = toHex(crib);

        String c1 = "3b101c091d53320c000910";
        String c2 = "071d154502010a04000419";
        String key = toHex("supersecret");
        assertEquals("7375706572736563726574", key);
        String c3 = xorHex(toHex("the mike"), key);
        System.out.println("C3:" + c3);
        String xor = xorHex(c1, c2);

        assertEquals("746865", cribHex);
        assertEquals("3c0d094c1f523808000d09", xor);

        String xor1 = xorHex(xor, cribHex);
        assertEquals("48656c", xor1);
        assertEquals("Hel", hexToAscii(xor1));

        String[] cribHexArray =
        {
            toHex("the"),
            toHex("Hel"),
            toHex("the "),
            toHex("Hell"),
            toHex("Hello"),
            toHex("Hello "),
            toHex("the p"),
            toHex("the pr"),
            toHex("ya"),
            toHex(" "),
            toHex("gram"),
            toHex("pro"),
            toHex("o W"),
            toHex("the program"),
            toHex("Hello World"),
            toHex("mike"),
        };
        Map<String, List<String>> map = new HashMap<String, List<String>>();

        System.out.println("Cipher Xor: " + xor);
        for (String cribString : cribHexArray)
        {
            String ascCrib = hexToAscii(cribString);

            for (int j = 0; j < xor.length(); j++)
            {
                String substring = xor.substring(j);

                String xor2 = xorHex(substring, cribString);

                if (!map.containsKey(ascCrib))
                {
                    map.put(ascCrib, new ArrayList<String>());
                }
                String hexToAscii = hexToAscii(xor2);
                String format = String.format("j:(%d) %s", j, hexToAscii);

                if (!hexToAscii.contains(INVALID_CHAR))
                {
                    List<String> get = map.get(ascCrib);
                    get.add(hexToAscii);
                }

            }

            //System.out.println("");
            //System.out.println("");
        }

        for (Map.Entry<String, List<String>> entry : map.entrySet())
        {
            String format = String.format("%s:\t %s", entry.getKey(), entry.getValue());
            System.out.print(format);
            System.out.println();
        }
    }

    @Test
    public void cipher1()
    {
        String[] cribHexArray =
        {
            toHex("the "),
            toHex("we can "),
            toHex("the second"),
            toHex("Ever us"),
            toHex(" the "),
            toHex(" and "),
            toHex("and"),
            toHex(" "),
            toHex("ssage"),
            toHex(" about"),
            toHex("toma"),
            toHex("the nup"),
            toHex("text produ"),
            toHex("d probably"),
            toHex("e"),
            toHex("t"),
            toHex("a"),
            toHex("o"),
        };

        Map<String, List<String>> map = new HashMap<String, List<String>>();
        String xorString = targetCipher;
        for (int i = 0; i < cipherTexts.length; i++)
        {
            xorString = xorHex(cipherTexts[i], xorString);

            for (String cribString : cribHexArray)
            {
                String ascCrib = hexToAscii(cribString);
                //System.out.println("Doing Crib: " + hexToAscii(cribString));
                for (int j = 0; j < xorString.length(); j++)
                {
                    String substring = xorString.substring(j);
                    // System.out.println("Substring: " + substring + " : " + i);
                    String xor2 = xorHex(substring, cribString);

                    if (!map.containsKey(ascCrib))
                    {
                        map.put(ascCrib, new ArrayList<String>());
                    }
                    String hexToAscii = hexToAscii(xor2);
                    String format = String.format("j:(%d) %s", j, hexToAscii);
                    //System.out.println(format);
                    if (!hexToAscii.contains(INVALID_CHAR))
                    {
                        List<String> get = map.get(ascCrib);
                        get.add(hexToAscii);
                    }

                }
                //System.out.println("");
                //System.out.println("");
            }
            System.out.println("");
        }


        for (Map.Entry<String, List<String>> entry : map.entrySet())
        {
            String format = String.format("%s: \t %s", entry.getKey(), entry.getValue());
            System.out.print(format);
            System.out.println();
        }
    }

    @Test
    public void cipher2()
    {
        String[] cribHexArray =
        {
            toHex("the "),
            toHex("we can "),
            toHex("the sec"),
            toHex("Ever us"),
            toHex(" the "),
            toHex(" and "),
            toHex("and"),
            toHex(" "),
            toHex("ssage"),
            toHex("sage in"),
            toHex(" about"),
            toHex("toma"),
            toHex("the nup"),
            toHex("text produ"),
            toHex("d probably"),
            toHex("e"),
            toHex("t"),
            toHex("a"),
            toHex("o"),
        };

        Map<String, List<String>> map = new HashMap<String, List<String>>();
        String xorString = targetCipher;
        for (int i = 0; i < cipherTexts.length; i++)
        {
            xorString = xorHex(cipherTexts[i], xorString);

            for (String cribString : cribHexArray)
            {
                //System.out.println("Doing Crib: " + hexToAscii(cribString));
                int length = xorString.length();

                String ascCrib = hexToAscii(cribString);
                for (int j = 0; j < xorString.length(); j += cribString.length())
                {
                    String substring = xorString.substring(j);
                    // System.out.println("Substring: " + substring + " : " + i);
                    String xor2 = xorHex(substring, cribString);

                    if (!map.containsKey(ascCrib))
                    {
                        map.put(ascCrib, new ArrayList<String>());
                    }
                    String hexToAscii = hexToAscii(xor2);
                    String format = String.format("j:(%d) %s", j, hexToAscii);
                    //System.out.println(format);
                    if (!hexToAscii.contains(INVALID_CHAR))
                    {
                        List<String> get = map.get(ascCrib);
                        get.add(hexToAscii);
                    }

                }
                //System.out.println("");
                //System.out.println("");
            }
            System.out.println("");
        }


        for (Map.Entry<String, List<String>> entry : map.entrySet())
        {
            String format = String.format("%s: \t %s", entry.getKey(), entry.getValue());
            System.out.print(format);
            System.out.println();
            System.out.println();
        }
    }

    @Test
    public void cipher3()
    {
        String[] cText = new String[cipherTexts.length + 1];
        System.arraycopy(cipherTexts, 0, cText, 0, cipherTexts.length);
        cText[cipherTexts.length] = targetCipher;

        String[][] xorMatrix = new String[cText.length][cText.length];
        //Get Matrix of All Cipher Texts xored with one another
        for (int i = 0; i < cText.length; i++)
        {
            for (int j = 0; j < cText.length; j++)
            {
                if (i != j)
                {
                    xorMatrix[i][j] = xorHex(cText[i], cText[j]);
                }
            }
        }

        String[] cribHexArray =
        {
            toHex("the"),
            toHex("the "),
            toHex(" the "),
            toHex("The "),
            toHex("priv"),
            toHex("The nic"),
            toHex("We can "),
            toHex("we can "),
            toHex("euler"),
            toHex("Ful"),
            toHex("here"),
            toHex("don"),
            toHex("e"),
            toHex("t"),
            toHex("at"),
            toHex(" "),
            toHex("Who"),
            toHex("What"),
            toHex("Where"),
            toHex("When"),
            toHex("Why"),
            toHex("How"),
            toHex("You"),
            toHex("you")
        };
        for (String cribHex : cribHexArray)
        {
            System.out.print("CribHex: " + hexToAscii(cribHex));
            System.out.println();
            for (String[] strings : xorMatrix)
            {
                for (String string : strings)
                {
                    if (string != null)
                    {
                        String xorHex = xorHex(string, cribHex);
                        System.out.print(hexToAscii(xorHex));
                    }
                }
                System.out.println();
            }
            System.out.println();
        }

    }

    @Test
    public void cipher4() throws UnsupportedEncodingException
    {
        //once we figure out one of the messages by crib-dragging, we can derive the key
        final String message0text = "We can factor the number 15 with quantum computers. We can also factor the number 15 with";
        //the key is the ciphertext of the message found (in this case message 0) XOR message0text
        String key = xorHex(cipherTexts[0], toHex(message0text));

        //now that we have the key for one message, we can also view all of the other messages
        for (String cipher : cipherTexts)
        {
            String mine = xorHex(key, cipher);
            System.out.println(hexToAscii(mine));
        }

        //use the key on the targeted cipher text
        String targetPlainText = xorHex(key, this.targetCipher);
        assertEquals("The secret message is: When using a stream cipher, never use the key more than once", hexToAscii(targetPlainText));
    }

    @Test
    public void exampleCipher()
    {
        String[] cText =
        {
            "3b101c091d53320c000910",
            "071d154502010a04000419"
        };

        String[][] xorMatrix = new String[cText.length][cText.length];
        //Get Matrix of All Cipher Texts xored with one another
        for (int i = 0; i < cText.length; i++)
        {
            for (int j = 0; j < cText.length; j++)
            {
                if (i != j)
                {
                    xorMatrix[i][j] = xorHex(cText[i], cText[j]);
                }
            }
        }


        String[] cribHexArray =
        {
            toHex("the"),
            toHex("the "),
            toHex("tel"),
            toHex("ya"),
            toHex("the         "),
            toHex("Hello"),
            toHex("Hello "),
            toHex(" W"),
            toHex("orld"),
            toHex("the pro"),
        };
        for (String cribHex : cribHexArray)
        {
            System.out.print("CribHex: " + hexToAscii(cribHex));
            System.out.println();
            for (String[] strings : xorMatrix)
            {
                for (String string : strings)
                {
                    if (string != null)
                    {
                        for (int j = 0; j < string.length(); j++)
                        {
                            String substring = string.substring(j);
                            // System.out.println("Substring: " + substring + " : " + i);

                            //String xorHex = xorHex(string, cribHex);
                            String xorHex = xorHex(substring, cribHex);
                            String hexToAscii = hexToAscii(xorHex);

                            if (!hexToAscii.contains("."))
                            {
                                System.out.print(hexToAscii + "|");
                            }

                        }
                    }

                }
                System.out.println();
            }
            System.out.println();
        }

    }

    @Test
    public void exampleCipher2() throws DecoderException
    {
        String[] cText =
        {
            "3b101c091d53320c000910",
            "071d154502010a04000419"
        };

        byte[][] xorMatrix = new byte[cText.length][cText[0].getBytes().length];
        //Get Matrix of All Cipher Texts xored with one another
        for (int i = 0; i < cText.length; i++)
        {
            try
            {
                xorMatrix[i] = Hex.decodeHex(cText[i].toCharArray());
            }
            catch (DecoderException ex)
            {
                Logger.getLogger(AppTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        for (int i = 0; i < xorMatrix.length; i++)
        {
//            try
//            {
            byte[] col = xorMatrix[i];
            System.out.print("[");
            for (byte b : col)
            {
                System.out.print(b + " ");
            }
            System.out.print("]");
            System.out.print("\t");
            String text = new String(col);
            System.out.print("\t");
            System.out.print(text);
            System.out.println();
            //System.out.println();
//
//                System.out.print("\t");
//                text = new String(Hex.decodeHex(text.toCharArray()));
//                System.out.print("\t");
//                System.out.print(text);
//                System.out.println();
//            }
//            catch (DecoderException ex)
//            {
//                Logger.getLogger(AppTest.class.getName()).log(Level.SEVERE, null, ex);
//            }
        }


        byte[] xor = xorBytes(xorMatrix[0], xorMatrix[1]);


        System.out.println("===================================================================================");
        System.out.print("[");
        for (byte b : xor)
        {
            System.out.print(b + " ");
        }
        System.out.print("]");
        System.out.print("\t");
        String text = new String(xor);
        System.out.print("\t");
        System.out.print("|" + text + "|");
        System.out.println();

        byte[] bite = xorBytes(xorMatrix[0], toHex(" ").getBytes());
        System.out.print("]");
        System.out.print("\t");
        text = new String(bite);
        System.out.print("\t");
        System.out.print("|" + text + "|");
        System.out.println();

//        System.out.println();
//        System.out.println("===================================");
//        byte[] xorBytes = xorBytes(xor, " ".getBytes());
//        text = new String(xorBytes);
//        System.out.print("\t");
//        System.out.print("|" + text + "|");
//        System.out.println();
//
//
//        System.out.println();
//        System.out.println("===================================");
//        xorBytes = xorBytes(xor, toHex(text).getBytes());
//        text = new String(xorBytes);
//        System.out.print("\t");
//        System.out.print("|" + text + "|");
//        System.out.println();



    }

    @Test
    public void homeworkQuestion5()
    {
        byte message = 127;
        byte key = 10 % 256;

        byte encrypt = (byte) (message + key);
        byte decrypt = (byte) (encrypt - key);
        assertEquals(message, decrypt);
        //message and key size are equal because of being bytes
    }

    @Test
    public void homeworkQuestion7() throws DecoderException
    {
        String hexEncrypt = "6c73d5240a948c86981bc294814d";
        String message = "attack at dawn";
        String key = xorHex(toHex(message), hexEncrypt);
        assertEquals("0d07a14569fface7ec3ba6f5f623", key);
        assertEquals(message, hexToAscii(xorHex(key, hexEncrypt)));

        String message2 = "attack at dusk";

        String hexEncrypt2 = xorHex(toHex(message2), key);
        System.out.println(hexEncrypt2);
        assertEquals("6c73d5240a948c86981bc2808548", hexEncrypt2);
        assertNotEquals(hexEncrypt, hexEncrypt2);

    }

    @Test
    public void homeworkQuestion7_attempt2() throws DecoderException
    {
        String hexEncrypt = "09e1c5f70a65ac519458e7e53f36";
        String message = "attack at dawn";
        String key = xorHex(toHex(message), hexEncrypt);
        System.out.println(key);
        assertEquals("6895b196690e8c30e07883844858", key);
        assertEquals(message, hexToAscii(xorHex(key, hexEncrypt)));

        String message2 = "attack at dusk";

        String hexEncrypt2 = xorHex(toHex(message2), key);
        System.out.println(hexEncrypt2);
        assertEquals("09e1c5f70a65ac519458e7f13b33", hexEncrypt2);
        assertNotEquals(hexEncrypt, hexEncrypt2);

    }

    public byte[] xorBytes(byte[] b1, byte[] b2)
    {
        int length = b1.length > b2.length ? b2.length : b1.length;
        byte[] xor = new byte[length];

        for (int i = 0; i < length; i++)
        {
            xor[i] = (byte) (b1[i] ^ b2[i]);
        }

        return xor;
    }
}