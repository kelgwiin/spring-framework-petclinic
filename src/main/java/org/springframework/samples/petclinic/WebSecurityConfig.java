/**
 *
 */
package org.springframework.samples.petclinic;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.samples.petclinic.config.MyAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author fromero
 *
 */
@EnableWebSecurity
@SuppressWarnings("deprecation")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

//    @Autowired
//    private DataSource dataSource;

    //custom-mod
//    @Override
//    @Bean
//    public UserDetailsService userDetailsService() {
//        JdbcDaoImpl usrSrv = new JdbcDaoImpl();
//        usrSrv.setDataSource(dataSource);
//
//        return usrSrv;
//    }

    @SuppressWarnings("deprecation")
    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }

    //custom-mod
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/webjars/**").permitAll()
            .anyRequest().authenticated()

            .and()
            .formLogin()
            .loginPage("/login")
            .successHandler(new MyAuthenticationSuccessHandler())
            .permitAll()

            .and()
            .x509()

            .and()
            .logout()
            .logoutUrl("/logout.html")
            .permitAll()
            .invalidateHttpSession(true)
//            .logoutSuccessHandler(this::handleSuccessRequest)
        ;
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .ldapAuthentication()
            .userDnPatterns("cn={0},ou=users")
            .groupSearchBase("ou=groups")
            .rolePrefix("ROLE_")
            .contextSource().ldif("classpath:users.ldif").root("o=belax")
            .and()
            .passwordCompare()
            .passwordAttribute("userPassword");
		/*
		 *  .groupRoleAttribute("cn") // ldap-authentication-provider@group-role-attribute
                    .groupSearchBase("ou=groups") // ldap-authentication-provider@group-search-base
                    .groupSearchFilter("(member={0})") // ldap-authentication-provider@group-search-filter
                    .rolePrefix("PREFIX_") // ldap-authentication-provider@group-search-filter
                    .userDetailsContextMapper(new PersonContextMapper()) // ldap-authentication-provider@user-context-mapper-ref / ldap-authentication-provider@user-details-class
                    .userDnPatterns("uid={0},ou=people") // ldap-authentication-provider@user-dn-pattern
                    .userSearchBase("ou=users") // ldap-authentication-provider@user-dn-pattern
                    .userSearchFilter("(uid={0})") // ldap-authentication-provider@user-search-filter
                    // .contextSource(contextSource) // ldap-authentication-provider@server-ref
                    .contextSource()
                        .ldif("classpath:user.ldif") // ldap-server@ldif
                        .managerDn("uid=admin,ou=system") // ldap-server@manager-dn
                        .managerPassword("secret") // ldap-server@manager-password
                        .port(33399) // ldap-server@port
                        .root("dc=springframework,dc=org") // ldap-server@root
                        // .url("ldap://localhost:33389/dc-springframework,dc=org") this overrides root and port and is used for external
                          */

	}

    private void handleSuccessRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                      Authentication authentication) throws IOException, ServletException {
        RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
        String targetUrl = "/";

        logger.info("Performed logout, thrown exceptions do not affect logout process");
        redirectStrategy.sendRedirect(httpServletRequest, httpServletResponse, targetUrl);
    }
}
