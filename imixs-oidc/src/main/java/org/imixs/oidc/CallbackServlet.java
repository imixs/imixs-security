package org.imixs.oidc;

import java.io.IOException;

import jakarta.inject.Inject;
import jakarta.security.enterprise.authentication.mechanism.http.openid.OpenIdConstant;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The CallbackServlet provides the callback URL for the identity provider. It
 * simply sends a redirect to the origin address
 */
@WebServlet("/callback")
public class CallbackServlet extends HttpServlet {
    @Inject
    private OpenIdContext context;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendRedirect(request.getSession().getAttribute(OpenIdConstant.ORIGINAL_REQUEST).toString());
    }
}