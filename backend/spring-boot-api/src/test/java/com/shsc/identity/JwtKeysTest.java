package com.shsc.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.shsc.identity.token.JwtKeys;

class JwtKeysTest {

    @Test
    void derivesThePublicKeyAndAStableKeyId() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        String encoded = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        JwtKeys keys = JwtKeys.fromBase64Pkcs8(encoded);

        assertThat(keys.publicKey().getW()).isEqualTo(((ECPublicKey) pair.getPublic()).getW());
        assertThat(keys.keyId()).isEqualTo(JwtKeys.fromBase64Pkcs8(encoded).keyId()).isNotBlank();
    }

    @Test
    void rejectsMissingOrInvalidKeys() throws Exception {
        assertThatThrownBy(() -> JwtKeys.fromBase64Pkcs8("")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> JwtKeys.fromBase64Pkcs8("bm90LWEta2V5")).isInstanceOf(IllegalStateException.class);

        KeyPairGenerator p384 = KeyPairGenerator.getInstance("EC");
        p384.initialize(new ECGenParameterSpec("secp384r1"));
        String wrongCurve = Base64.getEncoder().encodeToString(p384.generateKeyPair().getPrivate().getEncoded());
        assertThatThrownBy(() -> JwtKeys.fromBase64Pkcs8(wrongCurve)).isInstanceOf(IllegalStateException.class);
    }
}
