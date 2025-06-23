package org.imixs.security.oidc;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * This handler is responsible to redirect the user during the oidc
 * authentication flow
 */
@ApplicationScoped
public class OidcAuthFlowHandler {

    @Inject
    OidcConfig oidcConfig;

    public jakarta.security.enterprise.AuthenticationStatus handle(HttpServletRequest request,
            HttpServletResponse response,
            HttpMessageContext context) throws IOException {
        if (request.getRequestURI().contains("/callback")) {
            // handled by callbackServlet
            return context.doNothing(); // close OIDC Flow
        }

        // store original request path
        String originalRequest = request.getRequestURI();
        String query = request.getQueryString();
        if (query != null && !query.isEmpty()) {
            originalRequest += "?" + query;
        }
        HttpSession session = request.getSession(true);
        session.setAttribute("originalRequest", originalRequest);

        // start redirect
        String providerAuthEndpoint = oidcConfig.getAuthorizationEndpoint();
        String loginUrl = providerAuthEndpoint + "?response_type=code"
                + "&client_id=" + URLEncoder.encode(oidcConfig.getClientId(), StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(oidcConfig.getRedirectURI(), StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(oidcConfig.getScope(), StandardCharsets.UTF_8);

        response.sendRedirect(loginUrl);
        return jakarta.security.enterprise.AuthenticationStatus.SEND_CONTINUE;
    }
}