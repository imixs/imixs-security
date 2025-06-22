# OpenID Connect for Jakarta EE 10

This project provides a lightweight and extensible solution for integrating OpenID Connect (OIDC) authentication and Bearer token validation into a standard Jakarta EE application.

The library supports:

- ✅ OIDC login flow via standard OpenID Connect providers (e.g., Keycloak, Auth0, etc.)
- ✅ Bearer token validation for securing REST APIs
- ✅ JWT signature verification and expiration checks using Nimbus JOSE + JWT
- ✅ Token decoding and claim extraction via jakarta.json (no Jackson or extra dependencies)
- ✅ Clean separation of concerns (POJO-based, no framework lock-in)

**🔒 Security Highlights**

- Fetches and caches public keys from the OIDC provider's JWKS endpoint
- Verifies RSA signatures (RS256) with kid header resolution
- Validates exp claim to ensure token freshness
- Extracts username and roles from standard OIDC claims

More information:

- [Imixs Office Workflow OIDC](https://doc.office-workflow.com/auth/oidc/keycloak.html)
- [Jakarte EE Specification details](https://jakarta.ee/specifications/security/3.0/jakarta-security-spec-3.0.html#openid-connect-annotation)
- [Keycloak integration](https://docs.payara.fish/enterprise/docs/Technical%20Documentation/Public%20API/OpenID%20Connect%20Support.html)
- [Securing WildFly Apps](https://wildfly-security.github.io/wildfly-elytron/blog/securing-wildfly-apps-openid-connect/)

## Background

Since Jakarta EE 8 a new Security API provides a standard and portable way of handling security concerns in Java containers.
This new standard allows to configure the authentication mechanism of an application directly in a CDI bean, instead through the web.xml file. So web applications can now configure authentication mechanisms by providing implementations of the new `HttpAuthenticationMechanism` interface. Beside the standard implementations for Basic, Form and CustomForm authentication Jakarta EE 10 adapted this concept to provide an authentication mechanism for OpenID Connect. We introduced this library for an easy security setup of Web Applications.

## Maven Dependecy

The library can be added simply as a dependency to a web application project.
To use this library your application needs to be deployed into Jakarta EE 10 Application. You simply need to add the following maven dependencies to your pom.xml:

```xml
    <!-- Payara 5 OpenID Connect-->
    <dependency>
        <groupId>org.imixs.security</groupId>
        <artifactId>imixs-oidc</artifactId>
        <version>3.0.0-SNAPSHOT</version>
    </dependency>
```

The Jakarta EE 10 Runtime automatically scann this library during deployment and initializes the OpenID Connect auth mechanism automatically for your application. This is possible because of the `beans.xml` file located in the META-INF folder of this library. This library also includes a `CallbackServlet` that is used to redirect the user into your application after a successful login. So no additional implementation should be necessary.

## Configuration

The OpenID Client configuration attributes can be configured via Microprofile Config using the following properties :

| Environment Param       | Description                                           |
| ----------------------- | ----------------------------------------------------- |
| OIDCCONFIG_ISSUERURI    | endpoint for identity provider                        |
| OIDCCONFIG_CLIENTID     | OIDC Client ID                                        |
| OIDCCONFIG_CLIENTSECRET | Client secret                                         |
| OIDCCONFIG_REDIRECTURI  | Redirect URI - application address with /callback uri |

Note that the module provides a redirect servlet with the endpoint `/callback` this is the endpoint typically used by the identity provider as the callback uri. You will find more information about how to setup your identity provider in the [Imixs Office Workflow OIDC documentation pages](https://doc.office-workflow.com/auth/oidc/keycloak.html).

### Debug Mode

You can set the debug to true by setting the logger for 'org.imixs.security' at least to `FINE`. This prints more information during the login process and will help for a first setup.

**The Rest API Debug Endpoint**

The library also adds a rest API endpoint to provide OIDC debug information by the Rest API endpoint /oidc-debug:

    http://localhost:8080/api/oidc-debug

This endpoint will print details about the current OpenID session into the server log. The information can be helpful to analyze tokens and Claims returned by the OpenID provider.

```

=== Imixs-OIDC - Debug Information ===
Principal: anna

OIDC Claim:
===============================
{"exp":1750630586,
    "iat":1750630286,
    "auth_time":1750629115,
    "jti":"a2e213a2-aaaaaaaa-287e85280f2b",
    "iss":"http://keycloak.local:8084/realms/my-realm",
    "aud":"imixs",
    "sub":"c8d6a4b9-zzzzzzzzz-d6a19884d3a7",
    "typ":"ID",
    "azp":"imixs",
    "session_state":"974aaaf9-yyyyyyyyyyyy-624ed29de629",
    "at_hash":"hoE-ubXZ_34561tEHA0LOQ",
    "acr":"0",
    "sid":"974aaaf9-xxxxxxxx-624ed29de629",
    "email_verified":true,
    "name":"Anna M.",
    "groups":["default-roles-my-realm",
    "offline_access",
    "org.imixs.ACCESSLEVEL.AUTHORACCESS",
    "uma_authorization"],
    "preferred_username":"anna",
    "given_name":"Anna",
    "family_name":"M.",
    "email":"anna@foo.com"}
===============================
```

## The OidcContext

Imixs-Oidc provides a request scoped Bean holding OIDC context information. This bean can be used to resolve username, email or other parts from the OIDC claim.

See the following code example:

```java
    @Inject
    private OidcContext context;

    ....
    String userName = "" + context.getUsername();
    String email = "" + context.getEmail();

    // fetch a JsonObject object containing all claim information
    JsonObject claims = context.getClaims();
    // resolve roles
    List<STring> roles = claims.getJsonArray("groups").getValuesAs(v -> v.toString().replace("\"", ""));

```

## Integration

The following section contains information about integration into different server platforms.

### Wildfly

To Enable the OpenIdAuthenticationMechanismDefinition in Wildfly Server you need to disable the integrated jaspi module.

This can be done either by the wildfly-cli command:

    /subsystem=undertow/application-security-domain=other:add(security-domain=ApplicationDomain, integrated-jaspi=false)

or by changing the standalone.xml file:

```xml
            .......
            <application-security-domains>
                <!-- disable integrated jaspi! -->
                <application-security-domain name="other" security-domain="ApplicationDomain" integrated-jaspi="false" />
            </application-security-domains>
            .......
```

Find also other options for Wildfly here: https://wildfly-security.github.io/wildfly-elytron/blog/securing-wildfly-apps-openid-connect/

# Development

The following section contains information for developing custom implementations of a OpenIdAuthenticationMechanismDefinition

To build the library form sources you can run the maven command:

    $ mvn clean install

## The ClaimsDefinition

Within the OpenID standard it is not defined how Roles or Groups a user is assigned to are provided in a result token. For this reason it is necessary to declare with a so called `ClaimsDefinition` which attribute contains the groups to be resolved by the `OpenIdAuthenticationDefinition`.

For example if your provider sends the user roles in an attribute named `http://www.imixs.org/roles` you can map this information to the callerGroupsClaim.

```
@OpenIdAuthenticationDefinition( //
        providerURI = "${payara.security.openid.providerURI}", //
        ......
+       claimsDefinition = @ClaimsDefinition(callerGroupsClaim = "http://www.imixs.org/roles") //
)
```

When using this library you can set the GroupsClaim with the property `payara.security.openid.callerGroupsClaim`. This param dDefines the name of callerGroups claim and maps the claim’s value to caller groups value in IdentityStore#validate.

To setup Auth0 with user roles can be a little tricky but you will find a good tutorial [here](https://auth0.com/blog/jakarta-ee-oidc/).

## Auth0.com

For auth0.com you need to provide an additional parameter to resolve role names configured in auth0.com

    extraParameters = { "audience=https://<YOUR-DOMAIN>.auth0.com/api/v2/" }, //

## Protecting CDI Beans, EJBs and Pages

Within you application code you work with the usual Jakarta EE security API. There is no need to use any additional OpenID configuration or annotations.

The following example shows a EJB protected with the role 'super-admin'

```java
@DeclareRoles({ "org.imixs.ACCESSLEVEL.MANAGERACCESS" })
@RolesAllowed({ "org.imixs.ACCESSLEVEL.MANAGERACCESS" })
@Named
@RequestScoped
public class ConfigBean {
    @Inject
    Principal principal;

    // example how to get the user name
    public String getUsername() {
        return principal.getName();
    }
 ....
}
```

In the same way you can protect your EJBs.

```java
@DeclareRoles({ "org.imixs.ACCESSLEVEL.MANAGERACCESS" })
@RolesAllowed({ "org.imixs.ACCESSLEVEL.MANAGERACCESS" })
@Stateless
@LocalBean
public class ConfigService {
 ....
}
```

Protecting JSF pages or static html pages can be done as usual in the web.xml file:

```xml
 ....
	<security-constraint>
		<display-name>Custom Security Constraints</display-name>
		<web-resource-collection>
			<web-resource-name>AUTHENTICATED_RESOURCE</web-resource-name>
			<url-pattern>/pages/*</url-pattern>
			<url-pattern>/api/*</url-pattern>
		</web-resource-collection>
		<auth-constraint>
			<role-name>org.imixs.ACCESSLEVEL.MANAGERACCESS</role-name>
		</auth-constraint>
	</security-constraint>
	<security-role>
		<role-name>org.imixs.ACCESSLEVEL.MANAGERACCESS</role-name>
	</security-role>

....
```

**Note:** For Payara it is necessary to define a group/role mapping in the `WEB-INF/glassfish-web.xml` file. See the following example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE glassfish-web-app PUBLIC "-//GlassFish.org//DTD GlassFish Application Server 3.1 Servlet 3.0//EN" "http://glassfish.org/dtds/glassfish-web-app_3_0-1.dtd">
<glassfish-web-app>
	<context-root>/</context-root>

	<security-role-mapping>
		<role-name>org.imixs.ACCESSLEVEL.MANAGERACCESS</role-name>
		<group-name>org.imixs.ACCESSLEVEL.MANAGERACCESS</group-name>
	</security-role-mapping>

</glassfish-web-app>
```
