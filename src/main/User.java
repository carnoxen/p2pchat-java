package main;

import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public record User(
    String name,
    PublicKey publicKey,
    SecretKey secretKey,
    IvParameterSpec ivParameterSpec
) {}
