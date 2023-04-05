package com.glauberonobrega;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.TimeZone;

@SpringBootApplication
public class Application {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

        try {
            String seed20HexKey = Utils.generateSecretKey(20);
            String seed32HexKey = Utils.generateSecretKey(32);
            String seed64HexKey = Utils.generateSecretKey(64);

            long period = 30;
            int returnDigits = 6;
            long sync = 0;

            long unixTimestamp = Instant.now().getEpochSecond();
            long time = (unixTimestamp - sync) / period;

            StringBuilder counter = new StringBuilder(Long.toHexString(time).toUpperCase());

            while (counter.length() < 16)
                counter.insert(0, "0");

            String otpSHA1 = OTP.generateTOTP(seed20HexKey, counter.toString(), returnDigits, HmacHashFunction.SHA1);
            String otpSHA256 = OTP.generateTOTP(seed32HexKey, counter.toString(), returnDigits, HmacHashFunction.SHA256);
            String otpSHA512 = OTP.generateTOTP(seed64HexKey, counter.toString(), returnDigits, HmacHashFunction.SHA512);

            DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            df.setTimeZone(TimeZone.getTimeZone("UTC"));
            String fmtTime = String.format("%1$-11s", unixTimestamp);
            String utcTime = df.format(new Date(unixTimestamp * 1000));


            System.out.println("+---------------+-----------------------+" + "------------------+--------+-----------+");
            System.out.println("|  Time(sec)    |   Time (UTC format)   " + "| Value of T(Hex)  |  TOTP  | Algorithm |");
            System.out.println("+---------------+-----------------------+" + "------------------+--------+-----------+");
            System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + counter + " | ");
            System.out.println(otpSHA1 + " | SHA1      |");
            System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + counter + " | ");
            System.out.println(otpSHA256 + " | SHA256    |");
            System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + counter + " | ");
            System.out.println(otpSHA512 + " | SHA512    |");

            System.out.println("+---------------+-----------------------+" + "------------------+--------+-----------+");

            String accountName = "(otp.teste@glauberonobrega.com)";
            String issuerSHA1 = "Test OTP SHA1";

            String qrCodeDataSHA1 = GoogleAuthenticator.getTOTPURLSHA1(issuerSHA1, accountName, seed20HexKey, String.valueOf(returnDigits), String.valueOf(period));

            Utils.createQRCode(qrCodeDataSHA1, "/Users/Glauber/Projetos/OTPProject/src/main/resources/OTPProject_QRCode_SHA12.png", 340, 340);

        } catch (final Exception e) {
            System.out.println("Error : " + e);
        }
    }

}