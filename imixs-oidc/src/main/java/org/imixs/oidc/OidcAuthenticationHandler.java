package org.imixs.oidc;

import java.io.Serializable;
import java.security.Principal;
import java.util.logging.Logger;

import javax.annotation.security.RolesAllowed;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.security.enterprise.authentication.mechanism.http.OpenIdAuthenticationMechanismDefinition;
import jakarta.security.enterprise.identitystore.openid.AccessToken;
import jakarta.security.enterprise.identitystore.openid.IdentityToken;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;

/**
 * The class OidcAuthenticationHandler implements a
 * OpenIdAuthenticationMechanismDefinition for
 * Authentication against an OpenID Provider (e.g. Keycloak).
 * 
 * See also:
 * 
 * - https://auth0.com/blog/jakarta-ee-oidc/
 * - https://blogs.nologin.es/rickyepoderi/
 * 
 */
@RequestScoped
@Path("/oidc")
@Produces({ MediaType.TEXT_PLAIN })
@OpenIdAuthenticationMechanismDefinition( //
        clientId = "${oidcConfig.clientId}", //
        clientSecret = "${oidcConfig.clientSecret}", //
        redirectURI = "${oidcConfig.redirectURI}", //
        providerURI = "${oidcConfig.issuerUri}" //
)
public class OidcAuthenticationHandler implements Serializable {

    private static final long serialVersionUID = 1L;
    private static Logger logger = Logger.getLogger(OidcAuthenticationHandler.class.getName());

    @Inject
    Principal principal;

    @Inject
    private OpenIdContext context;

    /**
     * Debug endpoint prints session details into the server log
     * 
     * @return
     */
    @GET
    @Produces("text/plain")
    public String sessionInfoAuth(@Context HttpServletRequest request) {
        StringBuilder output = new StringBuilder();
        try {
            String forwardedProto = request.getHeader("X-Forwarded-Proto");
            output.append("\n=== OIDC Session Information ===\n")
                    .append("X-Forwarded-Proto: ").append(forwardedProto).append("\n");

            if (principal != null) {
                output.append("Principal: ").append(principal.getName()).append("\n");
            } else {
                String msg = "Warning: Principal resolved to null!";
                output.append(msg).append("\n");
            }

            if (context == null) {
                String msg = "Error: Failed to resolve OpenIdContext!";
                logger.severe(msg);
                return msg;
            }

            output.append("\nOIDC Details:\n")
                    .append("Subject: ").append(context.getSubject()).append("\n")
                    .append("Access Token: ").append(maskAccessToken(context.getAccessToken())).append("\n")
                    .append("ID Token: ").append(maskIdentityToken(context.getIdentityToken())).append("\n")
                    .append("Claims: ").append(formatJsonObject(context.getClaimsJson())).append("\n")
                    .append("===============================\n");

            logger.info(output.toString());
            return output.toString();

        } catch (Exception e) {
            String error = "Failed to resolve OpenIdContext: " + e.getMessage();
            logger.severe(error);
            return error;
        }
    }

    @GET
    @Path("/principal")
    @RolesAllowed("org.imixs.ACCESSLEVEL.MANAGERACCESS")
    @Produces("text/plain")
    public String getPrincipal() {
        logger.info("========> getPrincipal");
        return principal.getName();
    }

    // Access Token maskieren
    private String maskAccessToken(AccessToken token) {
        if (token == null)
            return "null";
        return token.getToken().substring(0, Math.min(token.getToken().length(), 20)) + "...";
    }

    private String maskIdentityToken(IdentityToken token) {
        if (token == null)
            return "null";
        return token.getToken().substring(0, Math.min(token.getToken().length(), 20)) + "...";
    }

    private String formatJsonObject(JsonObject json) {
        if (json == null)
            return "null";
        return json.toString().replaceAll(",", ",\n    ");
    }
}
