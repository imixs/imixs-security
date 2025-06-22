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
 */
@WebServlet("/callback")
public class CallbackServlet extends HttpServlet {
    private static Logger logger = Logger.getLogger(CallbackServlet.class.getName());

    @Inject
    OidcConfig oidcConfig;

    @Inject
    TokenValidator tokenValidator;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String code = request.getParameter("code");
        logger.info("├── callback code= " + code);
        if (code == null || code.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing authorization code");
            return;
        }

        // Token-Austausch
        TokenResponse token = exchangeAuthorizationCode(code);

        // ID Token decodieren mit TokenValidator
        String idToken = token.id_token;

        logger.fine("│   ├── idToken= " + idToken);
        try {
            Map<String, RSAKey> publicKeys = oidcConfig.getJwks();
            if (!TokenValidator.isTokenValid(idToken, publicKeys)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid ID token");
                return;
            }

            JsonObject claims = TokenValidator.decodeJwtPayload(idToken);

            String username = TokenValidator.extractUsername(claims);
            logger.info("│   ├── username=" + username);
            List<String> roles = TokenValidator.extractRoles(claims);
            if (roles != null && !roles.isEmpty()) {
                logger.info("│   ├── roles=" + String.join(", ", roles));
            } else {
                logger.warning("│   ├── unable to resolve roles");
                logger.warning("│   ├── claims=" + claims);
            }

            logger.info("│   ├── access_token=" + token.access_token);
            // Session setzen
            request.getSession().setAttribute("username", username);
            request.getSession().setAttribute("access_token", token.access_token);
            request.getSession().setAttribute("roles", roles);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Zurück zur ursprünglichen Seite
        String redirectTo = (String) request.getSession().getAttribute("originalRequest");
        logger.info("├── ✅ completed - redirect to: " + redirectTo);
        response.sendRedirect(redirectTo != null ? redirectTo : "/index.xhtml");
    }

    private TokenResponse exchangeAuthorizationCode(String code) throws IOException {
        HttpClient client = HttpClient.newHttpClient();
        logger.info("│   ├── exchangeAuthorizationCode=" + code);
        String body = "grant_type=authorization_code" +
                "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(oidcConfig.getRedirectURI(), StandardCharsets.UTF_8) +
                "&client_id=" + URLEncoder.encode(oidcConfig.getClientId(), StandardCharsets.UTF_8) +
                "&client_secret=" + URLEncoder.encode(oidcConfig.getClientSecret(), StandardCharsets.UTF_8);

        logger.info("│   ├── tokenEndpoint=" + oidcConfig.getTokenEndpoint());
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(oidcConfig.getTokenEndpoint()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response;
        try {
            response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            logger.info("│   ├── response statusCode=" + response.statusCode());
            if (response.statusCode() != 200) {
                throw new IOException("Token exchange failed: " + response.body());
            }

            try (JsonReader reader = Json.createReader(new StringReader(response.body()))) {
                JsonObject json = reader.readObject();
                logger.fine("│   ├── json response= " + json);

                String accessToken = json.getString("access_token", null);
                String idToken = json.getString("id_token", null);
                String refreshToken = json.getString("refresh_token", null);
                String tokenType = json.getString("token_type", null);
                String scope = json.getString("scope", null);
                long expiresIn = json.getJsonNumber("expires_in").longValue();

                logger.fine("│   │   ├── access_token= " + accessToken);
                logger.fine("│   │   ├── id_token= " + idToken);
                logger.fine("│   │   ├── refresh_token= " + refreshToken);
                logger.fine("│   │   ├── token_type= " + tokenType);
                logger.info("│   │   ├── scope= " + scope);
                logger.info("│   │   ├── expires_in= " + expiresIn);
                TokenResponse token = new TokenResponse();
                token.access_token = accessToken;
                token.id_token = idToken;
                token.refresh_token = refreshToken;
                token.token_type = tokenType;
                token.scope = scope;
                token.expires_in = expiresIn;
                return token;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return null;
        }
    }
}
