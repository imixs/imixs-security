package org.imixs.security.oidc;

import java.io.Serializable;
import java.security.Principal;
import java.util.logging.Logger;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;

/**
 * The class OidcApi implements a rest api endpoint to debug oidc data
 * 
 */
@RequestScoped
@Path("/oidc-debug")
@Produces({ MediaType.TEXT_PLAIN })
public class OidcApi implements Serializable {

    private static final long serialVersionUID = 1L;
    private static Logger logger = Logger.getLogger(OidcApi.class.getName());

    @Inject
    Principal principal;

    @Inject
    private OidcContext context;

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

            output.append("\n=== Imixs-OIDC - Debug Information ===\n");

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

            output.append("\nOIDC Claim:\n")
                    .append("===============================\n")
                    .append("").append(formatJsonObject(context.getClaims())).append("\n")
                    .append("===============================\n");

            logger.info(output.toString());
            return output.toString();

        } catch (Exception e) {
            String error = "Failed to resolve OpenIdContext: " + e.getMessage();
            logger.severe(error);
            return error;
        }
    }

    private String formatJsonObject(JsonObject json) {
        if (json == null)
            return "null";
        return json.toString().replaceAll(",", ",\n    ");
    }
}