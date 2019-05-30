/**
 *
 */
package org.springframework.samples.petclinic;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.samples.petclinic.config.MyAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

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

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user").password("password").roles("USER").build());

        manager.createUser(User.withUsername("admin").password("root").roles("ADMIN").build());

        return manager;
    }

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
            .logout()
            .logoutSuccessHandler(
                (httpServletRequest, httpServletResponse, authentication) ->
                    logger.info("Performed logout, thrown exceptions do not affect logout process"));
    }
}
