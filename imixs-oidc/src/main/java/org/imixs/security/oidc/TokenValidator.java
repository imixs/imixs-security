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
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;

/**
 * The TokenValidator is used to validate OIDC access tokens against the
 * identity provider
 */
public class TokenValidator {
    private static final Logger logger = Logger.getLogger(TokenValidator.class.getName());

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

            logger.fine("├── ✅ token successful verified.");
            return true;

        } catch (Exception e) {
            logger.severe("├── ❌ error validating token: " + e.getMessage());
            return false;
        }
    }

    /**
     * This method extract the caller name from the claim object. If not provided
     * the method will default to preferred_username|sub|name
     * 
     * @param claims
     * @param claimCallerName
     * @return
     */
    public static String extractUsername(JsonObject claims, String claimCallerName) {
        if (claimCallerName == null || claimCallerName.isBlank()) {
            if (claims.containsKey("preferred_username")) {
                return claims.getString("preferred_username");
            } else if (claims.containsKey("sub")) {
                return claims.getString("sub");
            } else {
                return claims.getString("name");
            }
        }
        try {
            return claims.getString(claimCallerName);
        } catch (NullPointerException e) {
            logger.severe("├── ❌ error failed to resolve '" + claimCallerName + "' from claim!");
        }
        return null;
    }

    /**
     * This method extracts the roles form a given json path. If no path is
     * provided, the method automatically tries to extract the roles based on
     * default locations within the claims.
     * 
     * @param claims
     * @param claimPath
     * @return
     */
    public static List<String> extractRoles(JsonObject claims, String claimPath) {
        if (claimPath == null || claimPath.isBlank()) {
            // no claimpath provided - try default values...
            List<String> result = extractFromPath(claims, "roles");
            if (!result.isEmpty())
                return result;

            result = extractFromPath(claims, "groups");
            if (!result.isEmpty())
                return result;

            result = extractFromPath(claims, "realm_access.roles");
            return result;
        }

        return extractFromPath(claims, claimPath);
    }

    /**
     * Helper method to extract child fields
     * 
     * @param claims
     * @param path
     * @return
     */
    private static List<String> extractFromPath(JsonObject claims, String path) {
        // Handle path with dots (e.g. "groups.roles", "realm_access.roles")
        if (path.contains(".")) {
            String[] pathParts = path.split("\\.");
            JsonValue current = claims;

            // Navigate through the path
            for (String part : pathParts) {
                if (current instanceof JsonObject obj && obj.containsKey(part)) {
                    current = obj.get(part);
                } else {
                    return List.of(); // path not found
                }
            }

            return extractArrayAsStringList(current);
        } else {
            // Simple field name (e.g. "groups", "roles")
            if (claims.containsKey(path)) {
                return extractArrayAsStringList(claims.get(path));
            }
            return List.of();
        }
    }

    private static List<String> extractArrayAsStringList(JsonValue value) {
        if (value == null) {
            return List.of();
        }

        if (value instanceof JsonArray array) {
            return array.getValuesAs(v -> v.toString().replace("\"", ""));
        }

        // If it's not an array, return empty list
        return List.of();
    }
}
