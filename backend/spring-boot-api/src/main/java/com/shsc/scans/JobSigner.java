package com.shsc.scans;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import org.springframework.stereotype.Component;

import com.shsc.shared.config.ShscProperties;

/**
 * Signs the scan jobs sent to the agents (docs/03-AGENT-PROTOCOL.md §6) with an Ed25519 key
 * that only the backend holds. Agents pin the public key ({@link #publicKey()}) at enrollment
 * and refuse a job whose signature does not verify, even if the TLS channel were compromised.
 * <p>
 * The key comes from {@code SHSC_JOB_SIGNING_KEY} (base64 PKCS#8 DER, as produced by
 * {@code openssl genpkey -algorithm ed25519}). The JDK cannot derive an Ed25519 public key
 * from a private key, so the key pair is regenerated deterministically from the 32-byte seed
 * contained in the PKCS#8 structure (RFC 8410), and the result is checked against the
 * configured private key.
 */
@Component
public class JobSigner {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final int SEED_LENGTH = 32;

    private final PrivateKey privateKey;
    private final byte[] publicKey;
    private final String keyId;

    public JobSigner(ShscProperties properties) {
        try {
            byte[] pkcs8 = Base64.getDecoder().decode(properties.scans().jobSigningKey().trim());
            PrivateKey configured = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            byte[] seed = Arrays.copyOfRange(pkcs8, pkcs8.length - SEED_LENGTH, pkcs8.length);
            KeyPair pair = fromSeed(seed);
            if (!Arrays.equals(pair.getPrivate().getEncoded(), configured.getEncoded())) {
                throw new IllegalStateException("SHSC_JOB_SIGNING_KEY is not a plain Ed25519 PKCS#8 key");
            }
            this.privateKey = configured;
            byte[] x509 = pair.getPublic().getEncoded();
            this.publicKey = Arrays.copyOfRange(x509, x509.length - SEED_LENGTH, x509.length);
            this.keyId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKey), 0, 8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("SHSC_JOB_SIGNING_KEY is not a valid base64 Ed25519 PKCS#8 key", e);
        }
    }

    /** Raw 32-byte public key, base64url without padding (format of the agent keys). */
    public String publicKey() {
        return B64URL.encodeToString(publicKey);
    }

    /** Short identifier of the key (first 8 bytes of SHA-256 of the public key, hex). */
    public String keyId() {
        return keyId;
    }

    /** Ed25519 signature of {@code payload}, base64url without padding. */
    public String sign(byte[] payload) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(payload);
            return B64URL.encodeToString(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot sign the scan job", e);
        }
    }

    private static KeyPair fromSeed(byte[] seed) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        generator.initialize(NamedParameterSpec.ED25519, new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                System.arraycopy(seed, 0, bytes, 0, Math.min(seed.length, bytes.length));
            }
        });
        return generator.generateKeyPair();
    }
}
