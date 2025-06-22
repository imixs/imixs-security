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

import com.nimbusds.jwt.JWTClaimsSet;

import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@WebServlet("/callback")
public class CallbackServlet extends HttpServlet {
    private static Logger logger = Logger.getLogger(CallbackServlet.class.getName());

    @Inject
    OidcConfig oidcConfig;

    // private final String clientId = "imixs";
    // private final String clientSecret = "hb3ZFc7uCtNm285ifcdedgK0l29Ur7Sh";
    // private final String redirectUri = "https://localhost:8181/callback";
    // private final String tokenEndpoint =
    // "http://keycloak.imixs.local:8084/realms/imixs-office-workflow/protocol/openid-connect/token";

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

        // ID Token decodieren (nur Demo – verwende eine JWT-Lib wie Nimbus)
        String idToken = token.id_token;
        logger.info("│   ├── idToken= " + idToken);
        JWTClaimsSet claims;
        try {
            claims = JwtUtils.validateToken(idToken);

            String username = claims.getStringClaim("preferred_username");
            logger.info("│   ├── username=" + username);

            // try to resolve user roles....
            List<String> roles = null;
            if (claims.getStringListClaim("roles") != null) {
                roles = claims.getStringListClaim("roles");
            } else if (claims.getStringListClaim("groups") != null) {
                roles = claims.getStringListClaim("groups");
            } else if (claims.getClaim("realm_access") != null) {
                Map<String, Object> realmAccess = (Map<String, Object>) claims.getClaim("realm_access");
                roles = (List<String>) realmAccess.get("roles");
            } else {
                logger.warning("│   ├── unable to resolve roles");
                logger.warning("│   ├── claims=" + claims);
            }
            if (roles != null) {
                logger.info("│   ├── roles=" + String.join(", ", roles));
            }

            logger.info("│   ├── access_token=" + token.access_token);
            // Session setzen
            request.getSession().setAttribute("username", username);
            request.getSession().setAttribute("access_token", token.access_token);
            request.getSession().setAttribute("roles", roles);
        } catch (Exception e) {
            // TODO Auto-generated catch block
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
                logger.info("│   ├── json response= " + json);

                String accessToken = json.getString("access_token", null);
                String idToken = json.getString("id_token", null);
                String refreshToken = json.getString("refresh_token", null);
                String tokenType = json.getString("token_type", null);
                String scope = json.getString("scope", null);
                long expiresIn = json.getJsonNumber("expires_in").longValue();

                logger.info("│   │   ├── access_token= " + accessToken);
                logger.info("│   │   ├── id_token= " + idToken);
                logger.info("│   │   ├── refresh_token= " + refreshToken);
                logger.info("│   │   ├── token_type= " + tokenType);
                logger.info("│   │   ├── scope= " + scope);
                logger.info("│   │   ├── expires_in= " + expiresIn);
                TokenResponse token = new TokenResponse();
                logger.info("│   ├── build token...");
                token.access_token = accessToken;
                token.id_token = idToken;
                token.refresh_token = refreshToken;
                token.token_type = tokenType;
                token.scope = scope;
                token.expires_in = expiresIn;
                return token;
            }
        } catch (IOException | InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}