package org.imixs.oidc;

import java.io.Serializable;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;

/**
 * The OidcConfig is a CDI config bean used to provide the config values for the
 * {@link OidcAuthenticationHandler}.
 * 
 * @author rsoika
 *
 */
@ApplicationScoped
@Named
public class OidcConfig implements Serializable {

    private static final long serialVersionUID = 7027147503119012594L;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_ISSUERURI", defaultValue = "http://localhost/")
    String issuerUri;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_CLIENTID", defaultValue = "undefined")
    String clientId;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_CLIENTSECRET", defaultValue = "undefined")
    String clientSecret;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_REDIRECTURI", defaultValue = "undefined")
    String redirectURI;

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getIssuerUri() {
        return issuerUri;
    }

    public String getRedirectURI() {
        if ("undefined".equals(redirectURI)) {
            // create default uri
            redirectURI = "${baseURL}/callback";
        }
        return redirectURI;
    }

}