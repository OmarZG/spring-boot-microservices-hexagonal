package com.example.microservices.auth.infrastructure.util;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Utility to generate RSA key pair for JWT signing
 * Run this once to generate private_key.pem and public_key.pem
 */
public class KeyGenerator {

    private static final String PRIVATE_KEY_FILE = "auth-service/src/main/resources/certs/private_key.pem";
    private static final String PUBLIC_KEY_FILE = "auth-service/src/main/resources/certs/public_key.pem";

    public static void main(String[] args) {
        try {
            System.out.println("Generating RSA key pair...");

            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Create certs directory if it doesn't exist
            Path certsDir = Paths.get("auth-service/src/main/resources/certs");
            Files.createDirectories(certsDir);

            // Save private key
            try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_FILE)) {
                fos.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
                fos.write(Base64.getMimeEncoder(64, "\n".getBytes()).encode(privateKey.getEncoded()));
                fos.write("\n-----END PRIVATE KEY-----\n".getBytes());
            }

            // Save public key
            try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILE)) {
                fos.write("-----BEGIN PUBLIC KEY-----\n".getBytes());
                fos.write(Base64.getMimeEncoder(64, "\n".getBytes()).encode(publicKey.getEncoded()));
                fos.write("\n-----END PUBLIC KEY-----\n".getBytes());
            }

            System.out.println("RSA key pair generated successfully!");
            System.out.println("Private key saved to: " + PRIVATE_KEY_FILE);
            System.out.println("Public key saved to: " + PUBLIC_KEY_FILE);
            System.out.println("\nIMPORTANT: Copy public_key.pem to product-service/src/main/resources/certs/");

        } catch (Exception e) {
            System.err.println("Error generating keys: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
