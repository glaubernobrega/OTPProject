package com.glauberonobrega;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class Utils {

    public static byte[] hexStr2Bytes(String hex) {
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();
        byte[] bytes = new byte[bArray.length - 1];
        System.arraycopy(bArray, 1, bytes, 0, bytes.length);
        return bytes;
    }

    public static String generateSecretKey(int length) {
        SecureRandom random = new SecureRandom();
        byte[] seed = new byte[length];
        random.nextBytes(seed);
        return Hex.encodeHexString(seed);
    }

    public static byte[] generateHmacHash(HmacHashFunction algorithm, byte[] keyBytes, byte[] text) {
        try {
            HmacHashFunction alg = algorithm;
            String crypto = alg.getAlgorithm();

            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }
    public static String hexStr2Base32(String hex) {
        byte[] bytes = hexStr2Bytes(hex);

        String base32 = new Base32().encodeToString(bytes);

        return base32;
    }

    public static void createQRCode(String qrCodeData, String filePath, int height, int width) throws WriterException, IOException {
        BitMatrix matrix = new MultiFormatWriter().encode(qrCodeData, BarcodeFormat.QR_CODE, width, height);
        try (FileOutputStream out = new FileOutputStream(filePath)) {
            MatrixToImageWriter.writeToStream(matrix, "png", out);
        }
    }
}
