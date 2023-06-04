package org.imixs.oidc;

import java.util.logging.Logger;
import java.util.Collections;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;

@ApplicationScoped
public class DemoGroupsIdentityStore implements IdentityStore {

   // private static final Object PROVIDE_GROUPS = null;

   private static Logger logger = Logger.getLogger(DemoGroupsIdentityStore.class.getName());

    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {
        logger.info("========> getCallerGroups");
       // Retrieve groups based on validationResult.getCallerPrincipal()
       return Collections.singleton("all");
 
    }
 
    @Override
    public Set<ValidationType> validationTypes() {
        logger.info("========> validationTypes");
       return Collections.singleton(null);
    }
    
}
