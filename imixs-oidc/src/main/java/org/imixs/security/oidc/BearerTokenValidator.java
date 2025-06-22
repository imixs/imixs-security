package org.imixs.security.oidc;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.RSAKey;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;

/**
 * The BearerTokenValidator provides static utility methods to validate and
 * decode Bearer JWT tokens.
 * 
 * It supports RS256 signed tokens based on the public keys (JWKS) fetched from
 * a trusted* OpenID Connect (OIDC) provider. The class verifies the token
 * signature and expiration.
 * 
 * It also allows extracting standard claims like username and roles from the
 * token.
 */
@ApplicationScoped
public class BearerTokenValidator {

    private static final Logger logger = Logger.getLogger(BearerTokenValidator.class.getName());

    @Inject
    OidcConfig oidcConfig;

    @Inject
    TokenValidator tokenValidator;

    public jakarta.security.enterprise.AuthenticationStatus handle(HttpServletRequest request,
            HttpMessageContext context) {

        logger.info("Hier bin ich");
        if (oidcConfig != null) {
            logger.info("oidcConfig is OK");
        } else {
            logger.info("oidcConfig is NOT OK");
        }
        String authHeader = request.getHeader("Authorization");
        logger.info("│   ├── Authorization header: " + authHeader);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring("Bearer ".length());
            logger.info("├── Bearer token validation...");
            try {
                // check signature + expires date
                Map<String, RSAKey> publicKeys = oidcConfig.getJwks();
                if (!TokenValidator.isTokenValid(token, publicKeys)) {
                    logger.warning("│   ├── ❌ invalid JWT-Token (signature/expires)");
                    return context.responseUnauthorized();
                }

                // extract Claims
                JsonObject claims = TokenValidator.decodeJwtPayload(token);

                String username = TokenValidator.extractUsername(claims);
                if (username == null || username.isBlank()) {
                    logger.warning("│   ├── ❌ no username found in token.");
                    return context.responseUnauthorized();
                }
                logger.info("│   ├── username=" + username);

                List<String> roles = TokenValidator.extractRoles(claims);
                if (roles != null && !roles.isEmpty()) {
                    logger.info("│   ├── roles=" + String.join(", ", roles));
                } else {
                    logger.warning("│   ├── unable to resolve roles");
                    logger.warning("│   ├── claims=" + claims);
                }

                logger.info("├── ✅ Authorization successful ");

                return context.notifyContainerAboutLogin(() -> username, new HashSet<>(roles));
            } catch (Exception e) {
                logger.warning("Invalid JWT token: " + e.getMessage());
                return context.responseUnauthorized();
            }
        } else {
            logger.warning("├── no Bearer token found!");
        }

        return context.responseUnauthorized();
    }
}