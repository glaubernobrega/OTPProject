package com.glauberonobrega;

public enum HmacHashFunction {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA1"),
    SHA512("HmacSHA1");
    private String value;
    public String getAlgorithm() {
        return value;
    }
    private HmacHashFunction(String value) {
        this.value = value;
    }
}
