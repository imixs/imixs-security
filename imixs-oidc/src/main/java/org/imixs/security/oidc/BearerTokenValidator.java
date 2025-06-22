package org.imixs.security.oidc;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;
import jakarta.servlet.http.HttpServletRequest;

@ApplicationScoped
public class BearerTokenValidator {

    @Inject
    IdentityStoreHandler identityStoreHandler;

    public jakarta.security.enterprise.AuthenticationStatus handle(HttpServletRequest request,
            HttpMessageContext context) {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring("Bearer ".length());
            JwtCredential credential = new JwtCredential(token);

            CredentialValidationResult result = identityStoreHandler.validate(credential);
            if (result.getStatus() == CredentialValidationResult.Status.VALID) {
                return context.notifyContainerAboutLogin(result);
            }
        }

        return context.responseUnauthorized();
    }
}
