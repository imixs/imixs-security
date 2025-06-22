package org.imixs.security.oidc;

import java.io.IOException;
import java.util.HashSet;
import java.util.logging.Logger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@ApplicationScoped
public class CombinedAuthenticationMechanism implements HttpAuthenticationMechanism {
    private static Logger logger = Logger.getLogger(CombinedAuthenticationMechanism.class.getName());

    @Inject
    BearerTokenValidator bearerTokenValidator;

    @Inject
    OidcAuthFlowHandler oidcAuthFlowHandler;

    @Override
    public jakarta.security.enterprise.AuthenticationStatus validateRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpMessageContext context) throws AuthenticationException {

        String path = request.getRequestURI();

        try {
            if (path.startsWith("/api/")) {
                logger.info("│   ├── api request");
                return bearerTokenValidator.handle(request, context);
            } else if (path.startsWith("/callback")) {
                logger.info("│   ├── callback request");
                return context.doNothing(); // lassen wir durch
            } else {
                // Prüfen, ob der Benutzer in der Session bereits authentifiziert wurde
                var session = request.getSession(false);
                if (session != null && session.getAttribute("username") != null) {
                    String username = (String) session.getAttribute("username");
                    @SuppressWarnings("unchecked")
                    var roles = (java.util.List<String>) session.getAttribute("roles");
                    logger.fine("│   ├── session user found: " + username);
                    return context.notifyContainerAboutLogin(() -> username, new HashSet<>(roles));
                }
                logger.info("├── oidcAuth request (start new login)");
                logger.info("│   ├── validateRequest: " + path);
                return oidcAuthFlowHandler.handle(request, response, context);
            }
        } catch (IOException e) {
            throw new AuthenticationException("Error handling authentication", e);
        }
    }
}