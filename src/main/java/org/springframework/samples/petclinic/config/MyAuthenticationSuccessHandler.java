package org.springframework.samples.petclinic.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MyAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public MyAuthenticationSuccessHandler() {
        setUseReferer(true);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.info("Performed successful login, welcome!!");
        StringBuilder target = new StringBuilder();

        authentication.getAuthorities()
            .forEach(grantedAuthority -> {
                logger.info("Checking out Role.");

                target.append(this.getUrlByRole(grantedAuthority));

                logger.info(target);
            });

        String targetUrl = target.toString();
        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    private String getUrlByRole(GrantedAuthority grantedAuthority) {
        String response;
        if (grantedAuthority.getAuthority().equals("ROLE_USER")) {
            response = "/";
        } else if (grantedAuthority.getAuthority().equals("ROLE_ADMIN")) {
            response = "/admin/home";
        } else {
            throw new IllegalStateException();
        }
        return response;

    }
}
