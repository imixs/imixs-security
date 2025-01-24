# OpenID Connect for Payara 5 Platform

This project provides a generic library to setup an OpenID Connect security mechanism for web applications running in Payara 5. Payara 5 provide a custom implementation to support OpenID Connect. You can find details in [Gaurav Gupta Blogpost](https://blog.payara.fish/openid-connect-in-the-payara-platform-5.183) as also in the [Blogpost from Rudy De Busscher](https://blog.payara.fish/how-to-use-openidconnect-with-payara-platform-to-achieve-single-sign-on). This implementation was also inspired by [Andrew Hughes blogpost about Jakarta EE and OIDC](https://auth0.com/blog/jakarta-ee-oidc/).

**Note:** The `@OpenIdAuthenticationDefinition` used in this library is a proprietary extension from Payara 5. The implementation was later adapted into the [Jakarta Security API 3.0](https://jakarta.ee/specifications/security/3.0/) which is now part of Jakarta 10. We provide this library for projects still running on Payara 5.

## Background

Since Jakarta EE 8 a new Security API was introduced providing a new standard and portable way of handling security concerns in Java containers. This new standard allows to configure the authentication mechanism of an application directly in a CDI bean, instead through the web.xml file. So web applications can now configure authentication mechanisms by providing implementations of the new `HttpAuthenticationMechanism` interface. Beside the standard implementations for Basic, Form and CustomForm authentication Payara 5 adapted very early this concept to provide an authentication mechanism for OpenID Connect. To avoid to pollute the application code with proprietary code, we introduced this library which can be added simply as a dependency to a web application project.

**Note:** Also this solution is not perfect as it requires to create a custom build of your application code including this library. But it avoids the need to add code that implements the `fish.payara.security.annotations.OpenIdAuthenticationDefinition` directly.

## Maven Dependecy

To use this library your application needs to be deployed into Payara 5 Platform. You simply need to add the following maven dependencies to your pom.xml:

```xml
    <!-- Payara 5 OpenID Connect-->
    <dependency>
        <groupId>org.imixs.security</groupId>
        <artifactId>imixs-oidc-payara5</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </dependency>
```

Payara 5 automatically scann this library during deployment and initializes the OpenID Connect auth mechanism automatically for your application. This is possible because of the `beans.xml` file located in the META-INF folder of this library. This library also includes a `CallbackServlet` that is used to redirect the user into your application after a successful login. So no additional implementation should be necessary.

## Auth0 OIDC

For testing and also production you can easily setup an OpenID login account with [auth0](https://auth0.com/). The following quick-guide shows how to setup Auth0 for you local development:

If you have not already, [install the Auth0 CLI](https://github.com/auth0/auth0-cli#installation) and run auth0 login in a terminal:

```
$ ./auth0 login
✪ Welcome to the Auth0 CLI 🎊

An Auth0 tenant is required to operate this CLI.
To create one, visit: https://auth0.com/signup.

You may authenticate to your tenant either as a user with personal
credentials or as a machine via client credentials. For more
information about authenticating the CLI to your tenant, visit
the docs: https://auth0.github.io/auth0-cli/auth0_login.html

 How would you like to authenticate?  [Use arrows to move, type to filter, ? for more help]
> As a user
  As a machine
```

If you already have setup a tenant, you can check the existing domain with:

```
$ auth0 tenants list
===

  AVAILABLE TENANTS
  foo.eu.auth0.com
```

The tenant domain is your Auth0 domain and is needed for further configuration.

Now use the Auth0 CLI to create an OpenID Connect (OIDC) application:

```
auth0 apps create

    Name: my-test-app
    Description: Testing OpenID Connect
    Type: Regular Web Application
    Callback URLs: http://localhost:8080/callback
    Allowed Logout URLs: http://localhost:8080
```

The console output shows you the Auth0 domain and the OIDC client ID. However, you also need the client secret. You will find this on the dashboard when your are logged into [Auth0](https://manage.auth0.com).

<img src="doc/images/auth0-001.png">

## Configuration

The Payara5 OpenID Client configuration attributes can be configured via Microprofile Config using the following properties :

```
    payara.security.openid.providerURI
    payara.security.openid.clientId
    payara.security.openid.clientSecret
    payara.security.openid.redirectURI
```

Microprofile Config is part of Payara 5 and the properties value take precedence over @OpenIdAuthenticationDefinition annotation values.

Setting the properties in a Docker or a Kubernetes environment use the corresponding Unix style to name the variables:

```
    PAYARA_SECURITY_OPENID_PROVIDERURI
    PAYARA_SECURITY_OPENID_CLIENTID
    PAYARA_SECURITY_OPENID_CLIENTSECRET
    PAYARA_SECURITY_OPENID_REDIRECTURI
```

A full list of all possible configuration values can be found [on the Payara OpenID Connect Support page](https://docs.payara.fish/enterprise/docs/documentation/payara-server/public-api/openid-connect-support.html).

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

## Protecting CDI Beans, EJBs and Pages

Within you application code you work with the usual Jakarta EE security API. There is no need to use any additional OpenID configuration or annotations.

The following example shows a EJB protected with the role 'super-admin'

```java
@DeclareRoles({ "super-admin" })
@RolesAllowed({ "super-admin" })
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
@DeclareRoles({ "super-admin" })
@RolesAllowed({ "super-admin" })
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
			<role-name>super-admin</role-name>
		</auth-constraint>
	</security-constraint>
	<security-role>
		<role-name>super-admin</role-name>
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
		<role-name>super-admin</role-name>
		<group-name>super-admin</group-name>
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
