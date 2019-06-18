/**
 *
 */
package org.springframework.samples.petclinic;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.samples.petclinic.config.MyAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

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
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //custom-mod
public class WebSecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);
    private PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//
//    @Autowired
//    private DataSource dataSource;

    //custom-mod
//    @Override
//    @Bean
//    public UserDetailsService userDetailsService() {
////        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
////        manager.createUser(User.withUsername("user").password("password").roles("USER").build());
////
////        manager.createUser(User.withUsername("admin").password("root").roles("ADMIN").build());
////        return manager;
//
//        JdbcDaoImpl usrSrv = new JdbcDaoImpl();
//        usrSrv.setDataSource(dataSource);
//
//        return usrSrv;
//    }

//    @SuppressWarnings("deprecation")
//    @Bean
//    public static NoOpPasswordEncoder passwordEncoder() {
//        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
//    }

    @Bean
    public UserDetailsService userDetailsService() {
        // ensure the passwords are encoded properly
        User.UserBuilder users = User.builder().passwordEncoder(encoder::encode);
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(users.username("fromero").password("1234").roles("USER").build());
        manager.createUser(users.username("lrobbio").password("5678").roles("USER", "ADMIN").build());
        return manager;
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        auth.inMemoryAuthentication()
//            .withUser("fromero")
//            .password(encoder.encode("1234"))
//            .roles("USER")
//            .and()
//            .withUser("lrobbio")
//            .password(encoder.encode("5678"))
//            .roles("ADMIN");
//    }

    //custom-mod
//    @Override


    private void handleSuccessRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                      Authentication authentication) throws IOException, ServletException {
        RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
        String targetUrl = "/";

        logger.info("Performed logout, thrown exceptions do not affect logout process");
        redirectStrategy.sendRedirect(httpServletRequest, httpServletResponse, targetUrl);
    }

    //API

    @Configuration
    @Order(1)
    public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .antMatcher("/api/**")
                .csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint())

                .and().formLogin().loginProcessingUrl("/api/login").permitAll()
                .successHandler(new MySavedRequestAwareAuthenticationSuccessHandler())
                .failureHandler(new SimpleUrlAuthenticationFailureHandler())

                .and()
                .authorizeRequests()
                .anyRequest().hasRole("ADMIN")
                .and()
                .logout();
        }

        public final class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

            @Override
            public void commence(
                HttpServletRequest request,
                HttpServletResponse response,
                AuthenticationException authException) throws IOException {

                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Unauthorized");
            }
        }

        //

        public class MySavedRequestAwareAuthenticationSuccessHandler
            extends SimpleUrlAuthenticationSuccessHandler {

            private RequestCache requestCache = new HttpSessionRequestCache();

            @Override
            public void onAuthenticationSuccess(
                HttpServletRequest request,
                HttpServletResponse response,
                Authentication authentication)
                throws ServletException, IOException {

                SavedRequest savedRequest  = requestCache.getRequest(request, response);

                if (savedRequest == null) {
                    clearAuthenticationAttributes(request);
                    return;
                }
                String targetUrlParam = getTargetUrlParameter();
                if (isAlwaysUseDefaultTargetUrl()
                    || (targetUrlParam != null
                    && StringUtils.hasText(request.getParameter(targetUrlParam)))) {
                    requestCache.removeRequest(request, response);
                    clearAuthenticationAttributes(request);
                    return;
                }

                clearAuthenticationAttributes(request);
            }

            public void setRequestCache(RequestCache requestCache) {
                this.requestCache = requestCache;
            }
        }



    }

    @Configuration
    public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        /* (non-Javadoc)
         * @see org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter#configure(org.springframework.security.config.annotation.web.builders.HttpSecurity)
         */

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
                .logout()
                .logoutUrl("/logout.html")
                .permitAll()
                .invalidateHttpSession(true)
//            .logoutSuccessHandler(this::handleSuccessRequest)
            ;
        }

    }


}
