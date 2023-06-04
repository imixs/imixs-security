package org.imixs.oidc;

import java.io.Serializable;
import java.security.Principal;
import java.util.logging.Logger;

import javax.annotation.security.DeclareRoles;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import fish.payara.cdi.auth.roles.RolesPermitted;
import fish.payara.security.annotations.ClaimsDefinition;
import fish.payara.security.annotations.OpenIdAuthenticationDefinition;
import fish.payara.security.openid.api.OpenIdContext;

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
@OpenIdAuthenticationDefinition( //
        providerURI = "${payara.security.openid.providerURI}", //
        clientId = "${payara.security.openid.clientId}", //
        clientSecret = "${payara.security.openid.clientSecret}", //
        redirectURI = "${payara.security.openid.redirectURI}", //
        scope = {
                "email", "openid", "profile" }, //
        claimsDefinition = @ClaimsDefinition(callerGroupsClaim = "http://www.imixs.org/roles") //
)
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
    @Path("/allowed")
    @RolesPermitted({ "org.imixs.ACCESSLEVEL.MANAGERACCESS" })
    @Produces("text/plain")
    public String allowed() {
        logger.info("========> allowed");
        return "Allowed";
    }

    @GET
    @Path("/allowedVIP")
    @RolesAllowed("org.imixs.ACCESSLEVEL.MANAGERACCESS")
    @Produces("text/plain")
    public String allowedVIP() {
        logger.info("========> allowedVIP");
        return "Allowed for VIPs only!";
    }

    @GET
    @Path("/forbidden")
    @RolesAllowed("org.imixs.ACCESSLEVEL.MANAGERACCESS")
    @Produces("text/plain")
    public String forbidden() {
        logger.info("========> forbidden");
        return "Should not be here";
    }

    @GET
    @Produces("text/plain")
    public String hello() {
        return "Hello, World!";
    }

    @GET
    @Path("/debug")
    // @RolesAllowed({ "org.imixs.ACCESSLEVEL.MANAGERACCESS" })
    @Produces("text/plain")
    public String sessionInfoAuth() {

        StringBuilder stringBuilder = new StringBuilder();

        try {
            logger.info("collecting OpenID context information...");
            // Here's the caller name
            stringBuilder.append("\nCaller name = " + context.getCallerName());
            // Here's the caller groups
            stringBuilder.append("\nCaller groups = " + context.getCallerGroups());
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
