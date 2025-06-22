package org.imixs.security.oidc;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.logging.Logger;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class JwtUtils {
    private static Logger logger = Logger.getLogger(JwtUtils.class.getName());

    // Z. B.
    // https://keycloak.imixs.local:8084/realms/myrealm/protocol/openid-connect/certs
    private static final String JWKS_URL = "http://keycloak.imixs.local:8084/realms/imixs-office-workflow/protocol/openid-connect/certs";
    private static final String EXPECTED_ISSUER = "http://keycloak.imixs.local:8084/realms/imixs-office-workflow";
    private static final String EXPECTED_AUDIENCE = "imixs";

    public static JWTClaimsSet validateToken(String token) throws Exception {

        logger.info("├── validateToken= " + token);
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Hole den Key ID (kid) aus dem Token Header
        String kid = signedJWT.getHeader().getKeyID();
        logger.info("│   ├── KeyID= " + kid);

        // Lade JWKS vom Keycloak-Server
        JWKSet jwkSet = JWKSet.load(new URL(JWKS_URL));
        JWK jwk = jwkSet.getKeyByKeyId(kid);

        if (jwk == null) {
            throw new IllegalArgumentException("No key found for Key ID: " + kid);
        }

        // Public Key extrahieren
        RSAKey rsaKey = (RSAKey) jwk;
        RSAPublicKey publicKey = rsaKey.toRSAPublicKey();

        // Signatur verifizieren
        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        if (!signedJWT.verify(verifier)) {
            throw new SecurityException("Invalid JWT signature");
        }

        // Claims prüfen
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        if (!EXPECTED_ISSUER.equals(claims.getIssuer())) {
            throw new SecurityException("Invalid issuer: " + claims.getIssuer());
        }

        if (!claims.getAudience().contains(EXPECTED_AUDIENCE)) {
            throw new SecurityException("Invalid audience: " + claims.getAudience());
        }

        if (new Date().after(claims.getExpirationTime())) {
            throw new SecurityException("Token expired");
        }

        return claims;
    }
}