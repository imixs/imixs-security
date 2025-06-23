package org.imixs.security.oidc;

import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

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

    private static final long JWKS_REFRESH_INTERVAL_SECONDS = 600; // 10 minutes

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

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_SCOPE", defaultValue = "openid profile email")
    String scope;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_CLAIM_CALLERNAME", defaultValue = "preferred_username")
    Optional<String> claimCallerName;

    @Inject
    @ConfigProperty(name = "OIDCCONFIG_CLAIM_ROLES")
    Optional<String> claimRolePath;

    private JsonObject config;

    private Map<String, RSAKey> cachedJwks;
    private long lastFetchTimestamp = 0;

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

    public String getClaimCallerName() {
        if (claimCallerName.isPresent()) {
            return claimCallerName.get();
        }
        return null; // not defined
    }

    public String getClaimRolePath() {
        if (claimRolePath.isPresent()) {
            return claimRolePath.get();
        }
        return null; // not defined
    }

    /**
     * Returns the scopes separated by spaces. If the scope variabel contains ','
     * these characters will be removed automatically
     * 
     * @return
     */
    public String getScope() {
        return scope.replace(",", "");
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

    /**
     * Returns cached JWKS, refreshing from remote if stale or missing.
     */
    public synchronized Map<String, RSAKey> getJwks() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        boolean debug = logger.isLoggable(Level.FINE);
        if (cachedJwks == null || (now - lastFetchTimestamp) > JWKS_REFRESH_INTERVAL_SECONDS) {
            if (debug) {
                logger.info("├── ⏳ JWKS cache expired or missing. Fetching from provider...");
            }
            try {
                Map<String, RSAKey> newJwks = fetchJwksRemote();
                // update cache
                cachedJwks = newJwks;
                lastFetchTimestamp = now;
            } catch (Exception e) {
                // on error, discard cache
                if (cachedJwks != null) {
                    logger.warning("JWKS refresh failed, using cached version: " + e.getMessage());
                    return cachedJwks;
                }
                throw e; // throw only if no cache is available
            }
        } else {
            logger.fine("├── ✅ Using cached JWKS.");
        }

        return cachedJwks;
    }

    /**
     * Fetch JWKS directly from the provider (no cache).
     */
    private Map<String, RSAKey> fetchJwksRemote() throws Exception {
        boolean debug = logger.isLoggable(Level.FINE);
        String jwksUri = getJwksUri();
        if (debug) {
            logger.info("├── 📥 Fetching JWKS from: " + jwksUri);
        }
        try (InputStream is = new URL(jwksUri).openStream()) {
            JWKSet jwkSet = JWKSet.load(is);
            return jwkSet.getKeys().stream()
                    .filter(k -> k instanceof RSAKey)
                    .map(k -> (RSAKey) k)
                    .collect(Collectors.toMap(JWK::getKeyID, k -> k));
        }
    }
}