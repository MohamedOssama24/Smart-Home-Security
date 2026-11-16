package com.shsc.identity.token;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

/**
 * ES256 signing key of the access tokens, read from the environment
 * ({@code SHSC_JWT_PRIVATE_KEY}: base64 of a PKCS#8 DER P-256 key). The public key is
 * derived from the private one; the key id is its RFC 7638 thumbprint, ready for rotation.
 */
public final class JwtKeys {

    private final ECKey jwk;

    private JwtKeys(ECKey jwk) {
        this.jwk = jwk;
    }

    public static JwtKeys fromBase64Pkcs8(String base64) {
        if (base64 == null || base64.isBlank()) {
            throw new IllegalStateException("SHSC_JWT_PRIVATE_KEY is not set");
        }
        try {
            byte[] der = Base64.getMimeDecoder().decode(base64.trim());
            KeyFactory factory = KeyFactory.getInstance("EC");
            ECPrivateKey privateKey = (ECPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(der));

            ECNamedCurveParameterSpec p256 = ECNamedCurveTable.getParameterSpec("secp256r1");
            if (!privateKey.getParams().getOrder().equals(p256.getN())) {
                throw new IllegalStateException("SHSC_JWT_PRIVATE_KEY must be an EC P-256 key");
            }
            org.bouncycastle.math.ec.ECPoint q = p256.getG().multiply(privateKey.getS()).normalize();
            ECPoint w = new ECPoint(q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger());
            ECPublicKey publicKey = (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(w, privateKey.getParams()));

            ECKey withoutId = new ECKey.Builder(Curve.P_256, publicKey).privateKey(privateKey).build();
            ECKey jwk = new ECKey.Builder(withoutId).keyID(withoutId.computeThumbprint().toString()).build();
            return new JwtKeys(jwk);
        } catch (GeneralSecurityException | IllegalArgumentException | JOSEException e) {
            throw new IllegalStateException("SHSC_JWT_PRIVATE_KEY is not a valid base64 PKCS#8 EC key", e);
        }
    }

    public ECKey jwk() {
        return jwk;
    }

    public ECPublicKey publicKey() {
        try {
            return jwk.toECPublicKey();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public String keyId() {
        return jwk.getKeyID();
    }
}
