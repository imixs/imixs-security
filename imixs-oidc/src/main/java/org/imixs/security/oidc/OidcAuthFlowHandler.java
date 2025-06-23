package org.imixs.security.oidc;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * This handler is responsible to redirect the user during the oidc
 * authentication flow
 */
// @ApplicationScoped
@RequestScoped
public class OidcAuthFlowHandler {
    private static Logger logger = Logger.getLogger(OidcAuthFlowHandler.class.getName());

    @Inject
    OidcConfig oidcConfig;

    public jakarta.security.enterprise.AuthenticationStatus handle(HttpServletRequest request,
            HttpServletResponse response,
            HttpMessageContext context) throws IOException {
        if (request.getRequestURI().contains("/callback")) {
            // handled by callbackServlet
            return context.doNothing(); // close OIDC Flow
        }

        boolean debug = logger.isLoggable(Level.FINE);

        // store original request path
        String originalRequest = request.getRequestURI();
        String query = request.getQueryString();
        if (query != null && !query.isEmpty()) {
            originalRequest += "?" + query;
        }

        HttpSession session = request.getSession(true);
        synchronized (session) {
            session.setAttribute("originalRequest", originalRequest);
        }

        // start redirect
        String providerAuthEndpoint = oidcConfig.getAuthorizationEndpoint();
        if (debug) {
            logger.info("├── starting OIDC Auth Flow...");
            logger.info("│   ├── providerAuthEndpoint=" + providerAuthEndpoint);
            logger.info("│   ├── client_id=" + oidcConfig.getClientId());
            logger.info("│   ├── redirect_uri=" + oidcConfig.getRedirectURI());
            logger.info("│   ├── scope=" + oidcConfig.getScope());
        }
        String loginUrl = providerAuthEndpoint + "?response_type=code"
                + "&client_id=" + URLEncoder.encode(oidcConfig.getClientId(), StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(oidcConfig.getRedirectURI(), StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(oidcConfig.getScope(), StandardCharsets.UTF_8);

        response.sendRedirect(loginUrl);
        return jakarta.security.enterprise.AuthenticationStatus.SEND_CONTINUE;
    }
}