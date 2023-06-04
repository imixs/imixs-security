package org.imixs.oidc;


import javax.annotation.security.DeclareRoles;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.annotation.HttpConstraint;
import javax.transaction.Transactional;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.List;
import java.io.Serializable;
import javax.naming.NamingException;
import fish.payara.cdi.auth.roles.RolesPermitted;
import fish.payara.security.annotations.ClaimsDefinition;
import fish.payara.security.annotations.OpenIdAuthenticationDefinition;
import fish.payara.security.openid.api.Claims;
import fish.payara.security.openid.api.OpenIdContext;
import java.util.logging.Logger;
import javax.ws.rs.core.MediaType;
/**
 * 
 * See: https://auth0.com/blog/jakarta-ee-oidc/
 * 
 */

// @Named
@RequestScoped
@Path("/hello")
@Produces({ MediaType.TEXT_PLAIN })
@DeclareRoles({ "org.imixs.ACCESSLEVEL.NOACCESS", "org.imixs.ACCESSLEVEL.READERACCESS",
"org.imixs.ACCESSLEVEL.AUTHORACCESS", "org.imixs.ACCESSLEVEL.EDITORACCESS",
"org.imixs.ACCESSLEVEL.MANAGERACCESS" })
@OpenIdAuthenticationDefinition(
        providerURI = "${payara.security.openid.providerURI}",
        clientId = "${payara.security.openid.clientId}",
        clientSecret = "${payara.security.openid.clientSecret}",
        redirectURI = "${payara.security.openid.redirectURI}",
        scope = {"email","openid","profile"}
        //claimsDefinition = @ClaimsDefinition(
        //        callerGroupsClaim = "b2xroles",
        //        callerNameClaim = "employeenumber"
        //)
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
      @RolesPermitted({"org.imixs.ACCESSLEVEL.MANAGERACCESS"})
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
      @Path("/session-info")
      @RolesAllowed({"org.imixs.ACCESSLEVEL.MANAGERACCESS"})
      @Produces("text/plain")
      public String sessionInfoAuth() {
          StringBuilder stringBuilder = new StringBuilder();
          //Here's the caller name
          stringBuilder.append("Caller name = " + context.getCallerName());
          //Here's the caller groups
          stringBuilder.append("Caller groups = " + context.getCallerGroups());
          //Here's the unique subject identifier within the issuer
          stringBuilder.append("Subject = " + context.getSubject());
          //Here's the access token
          stringBuilder.append("Access token = " + context.getAccessToken());
          //Here's the identity token
          stringBuilder.append("ID token = " + context.getIdentityToken());
          //Here's the user claims
          stringBuilder.append("Claims json = " + context.getClaimsJson());
          return stringBuilder.toString();
      }

}
