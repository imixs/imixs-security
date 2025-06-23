package org.imixs.security.oidc;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.RSAKey;

import jakarta.enterprise.context.RequestScoped;
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
 * 
 * In addition the BearerTokenValidator supports fetching additional claims
 * from the UserInfo endpoint when needed.
 * 
 */
@RequestScoped
public class BearerTokenValidator {

    private static final Logger logger = Logger.getLogger(BearerTokenValidator.class.getName());

    @Inject
    OidcConfig oidcConfig;

    @Inject
    OidcContext oidcContext;

    @Inject
    TokenValidator tokenValidator;

    @Inject
    UserInfoService userInfoService;

    public jakarta.security.enterprise.AuthenticationStatus handle(HttpServletRequest request,
            HttpMessageContext context) {

        boolean debug = logger.isLoggable(Level.FINE);

        String authHeader = request.getHeader("Authorization");
        if (debug) {
            logger.fine("│   ├── Authorization header: " + authHeader);
        }

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring("Bearer ".length());
            if (debug) {
                logger.info("├── Bearer token validation...");
            }

            try {
                // Validate token signature and expiration
                Map<String, RSAKey> publicKeys = oidcConfig.getJwks();
                if (!TokenValidator.isTokenValid(token, publicKeys)) {
                    logger.warning("│   ├── ❌ invalid JWT-Token (signature/expires)");
                    return context.responseUnauthorized();
                }

                // Extract initial claims from token
                JsonObject tokenClaims = TokenValidator.decodeJwtPayload(token);
                if (debug) {
                    logger.info("│   ├── token claims=" + tokenClaims);
                }

                // For Bearer tokens, the access token IS the token itself
                // Fetch additional user info if available
                JsonObject enrichedClaims = userInfoService.fetchAndMergeUserInfo(token, tokenClaims);

                // Extract username and roles from enriched claims
                String username = TokenValidator.extractUsername(enrichedClaims, oidcConfig.getClaimCallerName());
                if (username == null || username.isBlank()) {
                    logger.warning("│   ├── ❌ no username found in claims.");
                    return context.responseUnauthorized();
                }

                List<String> roles = TokenValidator.extractRoles(enrichedClaims, oidcConfig.getClaimRolePath());
                if (debug) {
                    logger.info("│   ├── username=" + username);
                    if (roles != null && !roles.isEmpty()) {
                        logger.info("│   ├── roles=" + String.join(", ", roles));
                    } else {
                        logger.warning("│   ├── unable to resolve roles");
                        logger.warning("│   ├── claims=" + enrichedClaims);
                    }
                }

                if (debug) {
                    logger.info("├── ✅ Authorization successful ");
                }

                // Provide request-scoped claim context with enriched claims
                oidcContext.initialize(enrichedClaims);

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