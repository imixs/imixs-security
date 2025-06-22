package org.imixs.security.oidc;

import java.io.StringReader;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.RSAKey;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

public class TokenValidator {
    private static final Logger logger = Logger.getLogger(TokenValidator.class.getName());

    // private Map<String, RSAKey> publicKeys;

    public static JsonObject decodeJwtPayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token format");
        }

        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
        try (JsonReader reader = Json.createReader(new StringReader(payloadJson))) {
            return reader.readObject();
        }
    }

    public static boolean isTokenValid(String jwt, Map<String, RSAKey> publicKeys) {
        try {
            JWSObject jwsObject = JWSObject.parse(jwt);
            JWSHeader header = jwsObject.getHeader();

            // Lade JWKS falls nicht vorhanden
            if (publicKeys != null) {

                String kid = header.getKeyID();
                RSAKey rsaKey = publicKeys.get(kid);
                if (rsaKey == null) {
                    logger.warning("├── ❌ no key found for kid=" + kid);
                    return false;
                }

                boolean valid = jwsObject.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(rsaKey.toRSAPublicKey()));
                if (!valid) {
                    logger.warning("├── ❌ signature verification failed.");
                    return false;
                }
            }

            // Optional: Ablaufdatum prüfen
            JsonObject claims = decodeJwtPayload(jwt);
            long now = System.currentTimeMillis() / 1000;
            if (claims.containsKey("exp")) {
                long exp = claims.getJsonNumber("exp").longValue();
                if (now > exp) {
                    logger.warning("├── ❌ token expired!");
                    return false;
                }
            }

            logger.info("├── ✅ token successful verified.");
            return true;

        } catch (Exception e) {
            logger.severe("├── ❌ error validating token: " + e.getMessage());
            return false;
        }
    }

    public static String extractUsername(JsonObject claims) {
        if (claims.containsKey("preferred_username")) {
            return claims.getString("preferred_username");
        } else if (claims.containsKey("sub")) {
            return claims.getString("sub");
        }
        return null;
    }

    public static List<String> extractRoles(JsonObject claims) {
        if (claims.containsKey("roles")) {
            return claims.getJsonArray("roles").getValuesAs(v -> v.toString().replace("\"", ""));
        } else if (claims.containsKey("groups")) {
            return claims.getJsonArray("groups").getValuesAs(v -> v.toString().replace("\"", ""));
        } else if (claims.containsKey("realm_access")) {
            JsonObject realmAccess = claims.getJsonObject("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                return realmAccess.getJsonArray("roles").getValuesAs(v -> v.toString().replace("\"", ""));
            }
        }
        return List.of();
    }

}
