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
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;

/**
 * @author fromero
 *
 */
@EnableWebSecurity
@SuppressWarnings("deprecation")
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //custom-mod
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    private DataSource dataSource;

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

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth.inMemoryAuthentication()
            .withUser("fromero")
            .password(encoder.encode("1234"))
            .roles("USER")
            .and()
            .withUser("lrobbio")
            .password(encoder.encode("5678"))
            .roles("ADMIN");
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
            .logout()
            .logoutUrl("/logout.html")
            .permitAll()
            .invalidateHttpSession(true)
//            .logoutSuccessHandler(this::handleSuccessRequest)
        ;
    }

    private void handleSuccessRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                      Authentication authentication) throws IOException, ServletException {
        RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
        String targetUrl = "/";

        logger.info("Performed logout, thrown exceptions do not affect logout process");
        redirectStrategy.sendRedirect(httpServletRequest, httpServletResponse, targetUrl);
    }
}
