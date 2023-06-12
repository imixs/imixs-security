package org.imixs.oidc;

import java.io.Serializable;
import java.security.Principal;
import java.util.logging.Logger;

import jakarta.annotation.security.DeclareRoles;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.authentication.mechanism.http.OpenIdAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.openid.ClaimsDefinition;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * 
 * See: https://auth0.com/blog/jakarta-ee-oidc/
 * 
 */

// @Named
@RequestScoped
@Path("/oidc")
@Produces({ MediaType.TEXT_PLAIN })
@DeclareRoles({ "org.imixs.ACCESSLEVEL.NOACCESS", "org.imixs.ACCESSLEVEL.READERACCESS",
        "org.imixs.ACCESSLEVEL.AUTHORACCESS", "org.imixs.ACCESSLEVEL.EDITORACCESS",
        "org.imixs.ACCESSLEVEL.MANAGERACCESS" })
@OpenIdAuthenticationMechanismDefinition( //
        clientId = "${oidcConfig.clientId}", //
        clientSecret = "${oidcConfig.clientSecret}", //
        redirectURI = "${baseURL}/callback", //
        providerURI = "${oidcConfig.issuerUri}", //
        tokenAutoRefresh = true, //
        // extraParameters = { "audience=https://<YOUR-DOMAIN>.eu.auth0.com/api/v2/" },
        // //
        claimsDefinition = @ClaimsDefinition(callerGroupsClaim = "http://www.imixs.org/roles")

)
// Caller Groups:
// OpenIdAuthenticationMechanismDefinition.claimsDefinition.callerGroupsClaim.
public class Securitybean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static Logger logger = Logger.getLogger(Securitybean.class.getName());

    @Inject
    Principal principal;

    @Inject
    private OpenIdContext context;

    @GET
    @Path("/principal")
    @RolesAllowed("org.imixs.ACCESSLEVEL.MANAGERACCESS")
    @Produces("text/plain")
    public String getPrincipal() {
        logger.info("========> getPrincipal");
        return principal.getName();
    }

    @GET
    @Produces("text/plain")
    public String hello() {
        return "Imixs Security - OIDC for Payara 5\n\n  /debug - show session details";
    }

    @GET
    @Path("/debug")
    // @RolesAllowed({ "org.imixs.ACCESSLEVEL.MANAGERACCESS" })
    @Produces("text/plain")
    public String sessionInfoAuth() {

        StringBuilder stringBuilder = new StringBuilder();

        try {
            logger.info("collecting OpenID context information...");

            // Here's the unique subject identifier within the issuer
            if (context.getSubject() == null) {
                stringBuilder.append("\nSubject = undefined");
            } else {
                stringBuilder.append("\nSubject = " + context.getSubject());
            }
            // Here's the access token
            stringBuilder.append("\nAccess token = " + context.getAccessToken());
            // Here's the identity token
            stringBuilder.append("\nID token = " + context.getIdentityToken());
            // Here's the user claims
            stringBuilder.append("\n\nClaims json = " + context.getClaimsJson());
        } catch (Exception e) {

            stringBuilder.append("\n\nFailed to resolve OpenIdContext: " + e.getMessage());
        }
        return stringBuilder.toString();
    }

}
