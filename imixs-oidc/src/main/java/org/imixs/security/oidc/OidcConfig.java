package org.imixs.security.oidc;

import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.logging.Logger;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

/**
 * The OidcConfig is a CDI config bean used to provide the config values for the
 * {@link Securitybean}.
 * 
 * @author rsoika
 *
 */
@ApplicationScoped
@Named
public class OidcConfig implements Serializable {

    private static final long serialVersionUID = 7027147503119012594L;
    private static final Logger logger = Logger.getLogger(OidcConfig.class.getName());

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_PROVIDERURI", defaultValue = "http://localhost/")
    String providerURI;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_CLIENTID", defaultValue = "undefined")
    String clientId;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_CLIENTSECRET", defaultValue = "undefined")
    String clientSecret;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_REDIRECTURI", defaultValue = "undefined")
    String redirectURI;

    private JsonObject config;

    @PostConstruct
    public void init() {
        this.config = fetchConfig(providerURI);
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getProviderURI() {
        return providerURI;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    private JsonObject fetchConfig(String issuerUri) {
        try {

            String discoveryUrl = issuerUri;

            // complete discoveryURL...
            if (!discoveryUrl.endsWith(".well-known/openid-configuration")) {
                if (!issuerUri.endsWith("/")) {
                    discoveryUrl += "/";
                }
                discoveryUrl += ".well-known/openid-configuration";
            }

            logger.info("├── Fetching OIDC config from: " + discoveryUrl);

            try (InputStream is = new URL(discoveryUrl).openStream();
                    JsonReader reader = Json.createReader(is)) {
                return reader.readObject();
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to load OIDC configuration from " + issuerUri, e);
        }
    }

    public String getAuthorizationEndpoint() {
        return config.getString("authorization_endpoint", null);
    }

    public String getTokenEndpoint() {
        return config.getString("token_endpoint", null);
    }

    public String getJwksUri() {
        return config.getString("jwks_uri", null);
    }

    public String getUserinfoEndpoint() {
        return config.getString("userinfo_endpoint", null);
    }

    public String getIssuer() {
        return config.getString("issuer", null);
    }

    public JsonObject getRawConfig() {
        return config;
    }

    public String getProviderUri() {
        return providerURI;
    }

}