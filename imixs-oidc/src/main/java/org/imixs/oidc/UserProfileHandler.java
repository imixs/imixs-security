package org.imixs.oidc;

import java.io.Serializable;
import java.nio.file.AccessDeniedException;
import java.security.Principal;
import java.util.logging.Logger;

import org.imixs.marty.profile.ProfileEvent;
import org.imixs.workflow.ItemCollection;

import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.security.enterprise.identitystore.openid.AccessToken;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;

/**
 * This class UserProfileHandler is a CDI Observer bean listening to updates of
 * a Imixs-Marty profile during the login process.
 * It automatically updates the user profile with the attributes provided by the
 * OpenID provider.
 * 
 */
@RequestScoped
public class UserProfileHandler implements Serializable {

    private static final long serialVersionUID = 1L;
    private static Logger logger = Logger.getLogger(OidcAuthenticationHandler.class.getName());

    @Inject
    Principal principal;

    @Inject
    private OpenIdContext context;

    /**
     * ProfileEvent listener to update a new profile with the user attributes
     * provided by the OpenID provider.
     * 
     * @param workflowEvent
     * @throws AccessDeniedException
     */
    public void onProfileEvent(@Observes ProfileEvent profileEvent) throws AccessDeniedException {

        int eventType = profileEvent.getEventType();

        ItemCollection profile = profileEvent.getProfile();
        if (profile == null) {
            return;
        }

        // reset orderItems if workItem has changed
        if (context != null
                && (ProfileEvent.ON_PROFILE_CREATE == eventType || ProfileEvent.ON_PROFILE_LOGIN == eventType)) {

            AccessToken accessToken = context.getAccessToken();
            String userName = "" + accessToken.getClaim("name");
            String email = "" + accessToken.getClaim("email");

            if (!email.equals(profile.getItemValueString("txtemail"))
                    || !userName.equals(profile.getItemValueString("txtusername"))) {
                logger.info("...update profile data...");
                profile.setItemValue("txtemail", email);
                profile.setItemValue("txtusername", userName);
            }

        }

    }

}
