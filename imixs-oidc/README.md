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

- [Jakarte EE Specification details](https://jakarta.ee/specifications/security/3.0/jakarta-security-spec-3.0.html)
- [Imixs Office Workflow OIDC](https://doc.office-workflow.com/auth/oidc/keycloak.html)
- [Keycloak integration](https://docs.payara.fish/enterprise/docs/Technical%20Documentation/Public%20API/OpenID%20Connect%20Support.html#keycloak-oidc-integration)

## Architecture

Imixs-OIDC implements a unified security architecture that supports both OpenID Connect (OIDC) login flows for browser-based applications and stateless Bearer token authentication for securing REST APIs. The solution is built entirely on top of the [Jakarta EE Security API](https://jakarta.ee/specifications/security/3.0/jakarta-security-spec-3.0.html).

At the core of the implementation is a custom `HttpAuthenticationMechanism`, which dynamically decides how to authenticate each incoming request. For regular browser-based access, the mechanism checks whether a valid user session already exists. If no session is present, the user is redirected into the standard OIDC authorization code flow. After a successful login, relevant user claims such as the username, roles, and email address are stored in the HTTP session and reused for subsequent requests. In case a Bearer token is detected in the Authorization header, the token is validated against the public keys of the OIDC provider using the Nimbus JOSE library.

The OIDC provider’s configuration and keys are discovered dynamically at application startup via the well-known endpoint and are cached in memory. This allows the application to remain compatible with any standards-compliant OIDC provider like Keycloak or Auth0 without additional dependencies. All parts of the authentication logic are implemented in a minimal, lightweight, and extensible way, leveraging only standard Jakarta EE features. The architecture ensures secure, token-based access for APIs while also providing a seamless login experience for web-based users—all within the same authentication mechanism.

## Maven Dependecy

The library can be added simply as a dependency to a web application project.
To use this library your application needs to be deployed into Jakarta EE 10 Application. You simply need to add the following maven dependencies to your pom.xml:

```xml
    <!-- Imixs-OpenID Connect-->
    <dependency>
        <groupId>org.imixs.security</groupId>
        <artifactId>imixs-oidc</artifactId>
        <version>3.0.0-SNAPSHOT</version>
    </dependency>
```

The Jakarta EE 10 Runtime automatically scann this library during deployment and initializes the OpenID Connect auth mechanism automatically for your application. This is possible because of the `beans.xml` file located in the META-INF folder of this library. This library also includes a `CallbackServlet` that is used to redirect the user into your application after a successful login. So no additional implementation should be necessary.

## Configuration

The OpenID Client configuration attributes can be configured via Microprofile Config using the following properties :

| Environment Param           | Description                                           |
| --------------------------- | ----------------------------------------------------- |
| OIDCCONFIG_ISSUERURI        | endpoint for identity provider                        |
| OIDCCONFIG_CLIENTID         | OIDC Client ID                                        |
| OIDCCONFIG_CLIENTSECRET     | Client secret                                         |
| OIDCCONFIG_REDIRECTURI      | Redirect URI - application address with /callback uri |
| OIDCCONFIG_SCOPE            | optional scope - defaults to "openid profile email"   |
| OIDCCONFIG_CLAIM_CALLERNAME | optional caller name from the claim                   |
| OIDCCONFIG_CLAIM_ROLES      | optional roles path within the claim                  |

Note that the module provides a redirect servlet with the endpoint `/callback` this is the endpoint typically used by the identity provider as the callback uri. You will find more information about how to setup your identity provider in the [Imixs Office Workflow OIDC documentation pages](https://doc.office-workflow.com/auth/oidc/keycloak.html).

### The Claims Username

The username (userid) is extracted form the OIDC access token. You can specify the claim attribute to resolve the username by the environment parameter `OIDCCONFIG_CLAIM_CALLERNAME`.
If not specified, Imixs-OIDC automatically resolves the user name to the options `preferred_username`, `sub` or `name` in this order.

### The Claims Role Path

The OpenID Connect Standard (OIDC) specifies the process of authentication and the format of ID tokens, but it does not impose binding requirements on how roles or groups must be included in the token. These are application-specific or provider-specific extensions that are handled differently by services such as Keycloak, Auth0, Azure AD, or Okta.
In practice, different variants of roles/groups in the access token can often be seen. Imixs-OIDC therefore automatically checks various variants to resolve the roles a user is assigned to.

You can configure the claim path used for extracting user roles from the access token by setting the `OIDCCONFIG_ROLES` property. For example:

    OIDCCONFIG_ROLES=realm_access.roles

This allows the application to support different OIDC providers like Keycloak, Auth0 or Azure AD without changing the source code. If no `OIDCCONFIG_ROLES` is defined, default locations will be applied to resolve the roles automatically.

## Bearer Token Authentication

The so called Resource Owner Password Credentials (ROPC) Flow allows your application to support a machine-to-machine communication. This is important for API clients that authenticate via access tokens, without requiring a browser-based login flow.

To authenticate against a protected API endpoint using a Bearer Token, you first need to obtain an access token from your OpenID Connect provider (e.g. Keycloak). This token is used for subsequent requests. The following example shows this flow by using the `curl` commandline tool:

**1. Request an Access Token**

```bash
curl -X POST \
  -d "grant_type=password" \
  -d "client_id=example-client" \
  -d "client_secret=your-client-secret" \
  -d "username=testuser" \
  -d "password=testpassword" \
  "http://your-keycloak-host/realms/your-realm/protocol/openid-connect/token"
```

This returns a JSON object containing the access_token. Example:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "token_type": "Bearer",
  ...
}
```

**2. Use the Token to Access Your API**

Copy the access_token and include it in the Authorization header of your API call:

```bash
curl -H "Authorization: Bearer eyJhbGciOi..." \
  http://your-api-host/api/resource
```

If the token is valid and your application is correctly configured, the server will return the protected resource.

## Debug Mode

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

### Payara

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
