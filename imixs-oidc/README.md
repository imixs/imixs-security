# OpenID Connect for Jakarta EE 10

This project provides a generic library to setup an OpenID Connect security mechanism for web applications running on Jakarta EE 10. Jakarta EE 10 provides a security API to support OpenID Connect. This implementation was also inspired by [Andrew Hughes blogpost about Jakarta EE and OIDC](https://auth0.com/blog/jakarta-ee-oidc/).

Specification details can be found [here](https://jakarta.ee/specifications/security/3.0/jakarta-security-spec-3.0.html#openid-connect-annotation).

## Background

Since Jakarta EE 8 a new Security API was introduced providing a new standard and portable way of handling security concerns in Java containers. This new standard allows to configure the authentication mechanism of an application directly in a CDI bean, instead through the web.xml file. So web applications can now configure authentication mechanisms by providing implementations of the new `HttpAuthenticationMechanism` interface. Beside the standard implementations for Basic, Form and CustomForm authentication Jakarta EE 10 adapted this concept to provide an authentication mechanism for OpenID Connect. We introduced this library for an easy security setup of Web Applications. The library can be added simply as a dependency to a web application project.

## Maven Dependecy

To use this library your application needs to be deployed into Jakarta EE 10 Application. You simply need to add the following maven dependencies to your pom.xml:

```xml
    <!-- Payara 5 OpenID Connect-->
    <dependency>
        <groupId>org.imixs.security</groupId>
        <artifactId>imixs-oidc</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </dependency>
```

The Jakarta EE 10 Runtime automatically scann this library during deployment and initializes the OpenID Connect auth mechanism automatically for your application. This is possible because of the `beans.xml` file located in the META-INF folder of this library. This library also includes a `CallbackServlet` that is used to redirect the user into your application after a successful login. So no additional implementation should be necessary.

## Configuration

The OpenID Client configuration attributes can be configured via Microprofile Config using the following properties :

```
      OIDCCONFIG_ISSUERURI: "<your provider url>"
      OIDCCONFIG_CLIENTID: "xxxxxxxxxx"
      OIDCCONFIG_CLIENTSECRET: "xxxxxxxxxx"
```

### The ClaimsDefinition

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

### Wildfly

To Enable the OpenIdAuthenticationMechanismDefinition in Wildfly Server you need to disalbe

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

### Auth0.com

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

## Debug

After you have configured the library and deployed your application you can request details about the authenticated user with the Rest API endpoint /debug:

    https://localhost:8181/api/oidc/debug

This information can be helpful to analyze tokens and Claims returned by the OpenID provider.

# Build from Sources

To build the library form sources you can run the maven command:

    $ mvn clean install
