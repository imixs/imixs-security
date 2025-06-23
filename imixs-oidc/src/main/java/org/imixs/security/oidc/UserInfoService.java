package org.imixs.security.oidc;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

/**
 * Service to fetch additional user information from the OIDC UserInfo endpoint.
 * This is necessary for providers like ForgeRock that don't include all claims
 * in the ID token but require a separate UserInfo request.
 */
@RequestScoped
public class UserInfoService {
    private static final Logger logger = Logger.getLogger(UserInfoService.class.getName());

    @Inject
    OidcConfig oidcConfig;

    /**
     * Fetches user information from the UserInfo endpoint using the access token
     * and merges it with existing claims from the ID token.
     * 
     * @param accessToken   The access token to authenticate the UserInfo request
     * @param idTokenClaims Existing claims from the ID token
     * @return JsonObject containing merged claims from ID token and UserInfo
     *         endpoint
     */
    public JsonObject fetchAndMergeUserInfo(String accessToken, JsonObject idTokenClaims) {

        if (!oidcConfig.isUserInfoEnabled()) {
            return idTokenClaims;
        }
        boolean debug = logger.isLoggable(Level.FINE);

        String userInfoEndpoint = oidcConfig.getUserinfoEndpoint();
        if (userInfoEndpoint == null || userInfoEndpoint.isEmpty()) {
            if (debug) {
                logger.fine("│   ├── No UserInfo endpoint configured, using ID token claims only");
            }
            return idTokenClaims;
        }

        if (accessToken == null || accessToken.isEmpty()) {
            logger.warning("│   ├── No access token available for UserInfo request");
            return idTokenClaims;
        }

        try {
            if (debug) {
                logger.info("│   ├── Fetching UserInfo from: " + userInfoEndpoint);
            }

            JsonObject userInfo = fetchUserInfo(accessToken, userInfoEndpoint);
            if (userInfo != null) {
                return mergeClaimsWithUserInfo(idTokenClaims, userInfo);
            } else {
                logger.warning("│   ├── UserInfo request failed, using ID token claims only");
                return idTokenClaims;
            }

        } catch (Exception e) {
            logger.warning("│   ├── Error fetching UserInfo: " + e.getMessage());
            return idTokenClaims;
        }
    }

    /**
     * Makes the actual HTTP request to the UserInfo endpoint
     */
    private JsonObject fetchUserInfo(String accessToken, String userInfoEndpoint)
            throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(userInfoEndpoint))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            try (JsonReader reader = Json.createReader(new StringReader(response.body()))) {
                JsonObject userInfo = reader.readObject();
                logger.fine("│   ├── UserInfo response: " + userInfo);
                return userInfo;
            }
        } else {
            logger.warning("│   ├── UserInfo request failed with status: " + response.statusCode());
            logger.warning("│   ├── Response body: " + response.body());
            return null;
        }
    }

    /**
     * Merges claims from ID token with UserInfo response.
     * UserInfo takes precedence for overlapping claims.
     */
    private JsonObject mergeClaimsWithUserInfo(JsonObject idTokenClaims, JsonObject userInfo) {
        // Start with ID token claims as base
        var mergedBuilder = Json.createObjectBuilder();

        // Add all claims from ID token
        idTokenClaims.forEach(mergedBuilder::add);

        // Override/add claims from UserInfo (UserInfo has precedence)
        userInfo.forEach((key, value) -> {
            mergedBuilder.add(key, value);
        });

        JsonObject merged = mergedBuilder.build();
        logger.fine("│   ├── Merged claims: " + merged);
        return merged;
    }
}