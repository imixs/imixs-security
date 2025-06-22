package org.imixs.security.oidc;

import java.io.IOException;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * CombinedAuthenticationMechanism provides a custom Jakarta Security
 * AuthenticationMechanism that supports both OpenID Connect (OIDC) login and
 * Bearer token authentication.
 *
 * This mechanism checks for an existing session-based OIDC login, or a Bearer
 * token in the Authorization header of an incoming request.
 * 
 * It delegates token validation to the BearerTokenValidator and integrates with
 * Jakarta Security APIs to register authenticated identity and roles.
 * 
 * This hybrid approach allows supporting browser-based logins and API clients
 * in a single security mechanism.
 */
@ApplicationScoped
public class OidcAuthenticationMechanism implements HttpAuthenticationMechanism {
    private static Logger logger = Logger.getLogger(OidcAuthenticationMechanism.class.getName());

    @Inject
    BearerTokenValidator bearerTokenValidator;

    @Inject
    OidcAuthFlowHandler oidcAuthFlowHandler;

    @Inject
    OidcConfig oidcConfig;

    @Inject
    OidcContext oidcContext;

    @Override
    public jakarta.security.enterprise.AuthenticationStatus validateRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpMessageContext context) throws AuthenticationException {

        try {
            boolean debug = logger.isLoggable(Level.FINE);
            // Test for Bearer token
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                if (debug) {
                    logger.info("│   ├── Bearer token detected");
                }
                return bearerTokenValidator.handle(request, context);
            }

            // Allow callback through without authentication
            String path = request.getRequestURI();
            if (path.startsWith("/callback")) {
                if (debug) {
                    logger.info("│   ├── callback request");
                }
                return context.doNothing();
            }

            // OIDC session-based login
            var session = request.getSession(false);
            if (session != null && session.getAttribute("username") != null) {
                String username = (String) session.getAttribute("username");
                @SuppressWarnings("unchecked")
                var roles = (java.util.List<String>) session.getAttribute("roles");
                logger.fine("│   ├── session user found: " + username);

                // Provide requestScoped claim context
                oidcContext.initialize((JsonObject) session.getAttribute("claims"));
                return context.notifyContainerAboutLogin(() -> username, new HashSet<>(roles));
            }
            if (debug) {
                logger.info("├── initiating OIDC login flow");
            }
            return oidcAuthFlowHandler.handle(request, response, context);

        } catch (IOException e) {
            throw new AuthenticationException("Error handling authentication", e);
        }
    }
}