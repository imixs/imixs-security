package org.imixs.security.oidc;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.RSAKey;

import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * The CallbackServlet provides the servlet endpoint for handling the OpenID
 * Connect (OIDC) authorization code callback.
 *
 * This servlet is triggered after a successful login at the identity provider
 * (IdP).
 * It exchanges the authorization code for an access token and stores the token
 * (and optionally user info) in the HTTP session.
 * 
 * This is a core part of the OIDC Authorization Code Flow.
 * 
 * In addition the CallbackServlet fetches additional user information
 * from the UserInfo endpoint when available.
 * 
 */
@WebServlet("/callback")
public class CallbackServlet extends HttpServlet {
    private static Logger logger = Logger.getLogger(CallbackServlet.class.getName());

    @Inject
    OidcConfig oidcConfig;

    @Inject
    UserInfoService userInfoService;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        boolean debug = logger.isLoggable(Level.FINE);
        String code = request.getParameter("code");
        if (debug) {
            logger.info("├── callback code= " + code);
        }
        if (code == null || code.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing authorization code");
            return;
        }

        // Exchange authorization code for tokens
        TokenResponse tokenResponse = exchangeAuthorizationCode(code);
        if (tokenResponse == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Token exchange failed");
            return;
        }

        // Validate and decode ID token
        String idToken = tokenResponse.id_token;
        logger.fine("│   ├── idToken= " + idToken);

        try {
            Map<String, RSAKey> publicKeys = oidcConfig.getJwks();
            if (!TokenValidator.isTokenValid(idToken, publicKeys)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid ID token");
                return;
            }

            // Extract claims from ID token
            JsonObject idTokenClaims = TokenValidator.decodeJwtPayload(idToken);
            if (debug) {
                logger.info("│   ├── ID token claims=" + idTokenClaims);
            }

            // Fetch additional user info using access token and merge with ID token claims
            JsonObject enrichedClaims = userInfoService.fetchAndMergeUserInfo(
                    tokenResponse.access_token, idTokenClaims);

            // Extract username and roles from enriched claims
            String username = TokenValidator.extractUsername(enrichedClaims, oidcConfig.getClaimCallerName());
            if (username == null) {
                throw new NullPointerException("Username resolved to null");
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

            // Store in session - use enriched claims instead of just ID token claims
            request.getSession().setAttribute("username", username);
            request.getSession().setAttribute("access_token", tokenResponse.access_token);
            request.getSession().setAttribute("roles", roles);
            request.getSession().setAttribute("claims", enrichedClaims); // Store enriched claims

            logger.info("├── ✅ OIDC Login successful ");

            // Redirect to original page
            HttpSession session = request.getSession();
            String redirectTo = (String) session.getAttribute("originalRequest");
            if (redirectTo != null) {
                session.removeAttribute("originalRequest");
            }
            if (redirectTo != null && !redirectTo.isEmpty()) {
                logger.info("├── ☑️ redirect to: " + redirectTo);
            }
            response.sendRedirect(redirectTo != null ? redirectTo : "/index.xhtml");

        } catch (Exception e) {
            logger.severe("├── ❌ OIDC Login error: " + e.getMessage());
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Login processing failed");
        }
    }

    private TokenResponse exchangeAuthorizationCode(String code) throws IOException {
        boolean debug = logger.isLoggable(Level.FINE);
        HttpClient client = HttpClient.newHttpClient();
        if (debug) {
            logger.info("│   ├── exchangeAuthorizationCode=" + code);
        }

        String body = "grant_type=authorization_code" +
                "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(oidcConfig.getRedirectURI(), StandardCharsets.UTF_8) +
                "&client_id=" + URLEncoder.encode(oidcConfig.getClientId(), StandardCharsets.UTF_8) +
                "&client_secret=" + URLEncoder.encode(oidcConfig.getClientSecret(), StandardCharsets.UTF_8);

        if (debug) {
            logger.info("│   ├── tokenEndpoint=" + oidcConfig.getTokenEndpoint());
        }

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(oidcConfig.getTokenEndpoint()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        try {
            HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            if (debug) {
                logger.info("│   ├── response statusCode=" + response.statusCode());
            }

            if (response.statusCode() != 200) {
                logger.warning("Token exchange failed with status " + response.statusCode() + ": " + response.body());
                return null;
            }

            try (JsonReader reader = Json.createReader(new StringReader(response.body()))) {
                JsonObject json = reader.readObject();
                logger.fine("│   ├── json response= " + json);

                TokenResponse token = new TokenResponse();
                token.access_token = json.getString("access_token", null);
                token.id_token = json.getString("id_token", null);
                token.refresh_token = json.getString("refresh_token", null);
                token.token_type = json.getString("token_type", null);
                token.scope = json.getString("scope", null);
                token.expires_in = json.getJsonNumber("expires_in") != null
                        ? json.getJsonNumber("expires_in").longValue()
                        : 0L;

                if (debug) {
                    logger.finest("│   │   ├── access_token= " + token.access_token);
                    logger.finest("│   │   ├── id_token= " + token.id_token);
                    logger.finest("│   │   ├── refresh_token= " + token.refresh_token);
                    logger.finest("│   │   ├── token_type= " + token.token_type);
                    logger.info("│   │   ├── scope= " + token.scope);
                    logger.info("│   │   ├── expires_in= " + token.expires_in);
                }

                return token;
            }
        } catch (IOException | InterruptedException e) {
            logger.severe("Error during token exchange: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}