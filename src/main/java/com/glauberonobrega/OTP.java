package com.glauberonobrega;

public class OTP {
    private static final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

    public static String generateTOTP(String key, String time, int returnDigits) {
        return generateTOTP(key, time, returnDigits, HmacHashFunction.SHA1);
    }

    public static String generateTOTP256(String key, String time, int returnDigits) {
        return generateTOTP(key, time, returnDigits, HmacHashFunction.SHA256);
    }

    public static String generateTOTP512(String key, String time, int returnDigits) {
        return generateTOTP(key, time, returnDigits, HmacHashFunction.SHA512);
    }

    public static String generateTOTP(String key, String time, int returnDigits, HmacHashFunction cryptoAlgorithm) {

        StringBuilder result = null;

        // Get the HEX in a Byte[]
        byte[] k = Utils.hexStr2Bytes(key);
        byte[] msg = Utils.hexStr2Bytes(time);
        byte[] hash = Utils.generateHmacHash(cryptoAlgorithm, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[returnDigits];

        result = new StringBuilder(Integer.toString(otp));
        while (result.length() < returnDigits)
            result.insert(0, "0");

        return result.toString();
    }
}
