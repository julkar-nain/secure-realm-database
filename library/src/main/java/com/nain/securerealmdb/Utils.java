package com.nain.securerealmdb;

/**
 * This is a utility class
 *
 * @author julkar nain
 * @since 3/27/19
 */
public class Utils {
    /**
     * This method convert byteArray into Hex String
     *
     * @param byteArray
     *
     * @return String
     * **/
    public static String encodeHexString(byte[] byteArray) {
        StringBuilder hexStringBuffer = new StringBuilder();
        for (byte singleByte : byteArray) {
            hexStringBuffer.append(byteToHex(singleByte));
        }

        return hexStringBuffer.toString();
    }

    /**
     * This method convert byteArray into Hex String
     *
     * @param hexString
     *
     * @return byte[]
     * **/
    public static byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    private static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if (digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: " + hexChar);
        }
        return digit;
    }

    private static String byteToHex(byte singleByte) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((singleByte >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((singleByte & 0xF), 16);

        return new String(hexDigits);
    }
}
