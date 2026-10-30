package com.sentinelstream.audit.domain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Ed25519 over UTF-8 text, JDK only. Keys travel as PEM (PKCS#8 private, X.509 public). */
public final class Ed25519Signer {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private Ed25519Signer(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public static Ed25519Signer generate() {
        try {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            return new Ed25519Signer(kp.getPrivate(), kp.getPublic());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Accepts a PKCS#8 private key PEM; the public key is derived from it. */
    public static Ed25519Signer fromPem(String pem) {
        try {
            byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", "").trim());
            PrivateKey priv = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
            // PKCS#8 v1 Ed25519 keys don't carry the public key; derive it by signing setup through the JDK
            PublicKey pub = derivePublic(der);
            return new Ed25519Signer(priv, pub);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalArgumentException("not an Ed25519 PKCS#8 private key");
        }
    }

    public String sign(String message) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(privateKey);
            s.update(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean verify(String message, String signatureB64) {
        return verify(publicKey, message, signatureB64);
    }

    public static boolean verify(PublicKey key, String message, String signatureB64) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(message.getBytes(StandardCharsets.UTF_8));
            return s.verify(Base64.getDecoder().decode(signatureB64));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    public String publicKeyPem() {
        return "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----\n";
    }

    public static PublicKey publicFromPem(String pem) throws GeneralSecurityException {
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", "").trim());
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * An Ed25519 PKCS#8 v1 body is a fixed 16-byte prefix plus the 32-byte seed. The public key is not
     * derivable through the public JDK API, so this computes it with the JDK's own key pair generator
     * seeded deterministically from the private seed.
     */
    private static PublicKey derivePublic(byte[] pkcs8) throws GeneralSecurityException {
        byte[] seed = java.util.Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
        g.initialize(new java.security.spec.NamedParameterSpec("Ed25519"), new FixedRandom(seed));
        KeyPair kp = g.generateKeyPair();
        if (!java.util.Arrays.equals(kp.getPrivate().getEncoded(), pkcs8)) {
            throw new GeneralSecurityException("unexpected key encoding");
        }
        return kp.getPublic();
    }

    private static final class FixedRandom extends java.security.SecureRandom {
        private final byte[] bytes;

        FixedRandom(byte[] bytes) {
            this.bytes = bytes.clone();
        }

        @Override
        public void nextBytes(byte[] out) {
            System.arraycopy(bytes, 0, out, 0, Math.min(bytes.length, out.length));
        }
    }
}
