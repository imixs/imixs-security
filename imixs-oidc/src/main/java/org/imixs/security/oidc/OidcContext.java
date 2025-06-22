package org.imixs.security.oidc;

import jakarta.enterprise.context.RequestScoped;
import jakarta.json.JsonObject;

@RequestScoped
public class OidcContext {
    private JsonObject claims;

    public void initialize(JsonObject claims) {
        this.claims = claims;
    }

    public String getUsername() {
        if (claims != null) {
            return claims.getString("preferred_username", null);
        }
        return null;
    }

    public String getEmail() {
        if (claims != null) {
            return claims.getString("email", null);
        }
        return null;
    }

    public JsonObject getClaims() {
        return claims;
    }

}