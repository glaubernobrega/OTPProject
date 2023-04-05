package com.glauberonobrega;

import org.apache.http.client.utils.URIBuilder;

public final class GoogleAuthenticator {

    private static String HOTP = "hotp";
    private static String TOTP = "totp";

    public static String getTOTPURLSHA1(String issuer, String accountName, String secret, String digits, String period) {
        return generateOTPURI(TOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, period, null);
    }

    public static String getTOTPURLSHA256(String issuer, String accountName, String secret, String digits, String period) {
        return generateOTPURI(TOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, period, null);
    }

    public static String getTOTPURLSHA512(String issuer, String accountName, String secret, String digits, String period) {
        return generateOTPURI(TOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, period, null);
    }

    public static String getHOTPURLSHA256(String issuer, String accountName, String secret, String digits, String counter) {
        return generateOTPURI(HOTP, issuer, accountName, secret, digits, HmacHashFunction.SHA1, null, counter);
    }

    private static String generateOTPURI(String method, String issuer, String accountName, String secret, String digits, HmacHashFunction algorithm, String period, String counter) {

        String secretBase32 = Utils.hexStr2Base32(secret);
        String hashAlgorithm = getAlgorithmName(algorithm);

        StringBuilder path = new StringBuilder();
        path.append("/");
        path.append(issuer);
        path.append(" ");
        path.append(accountName);

        URIBuilder uri = new URIBuilder();
        uri.setScheme("otpauth");
        uri.setHost(method);
        uri.setPath(path.toString());
        uri.setParameter("secret", secretBase32);
        uri.setParameter("algorithm", hashAlgorithm);
        uri.setParameter("digits", digits);

        if (method.equals("hotp"))
            uri.setParameter("counter", counter);

        if (method.equals("totp"))
            uri.setParameter("period", period);

        return uri.toString();
    }

    private static String getAlgorithmName(HmacHashFunction algorithm) {
        return switch (algorithm) {
            case SHA1 -> "SHA1";
            case SHA256 -> "SHA256";
            case SHA512 -> "SHA512";
            default -> throw new IllegalArgumentException(String.format("Unknown algorithm: %s", algorithm));
        };
    }
}
