package com.github.peacetrue.sample.oss.oidc;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

/**
 * @author : xiayx
 * @since : 2021-07-29 09:33
 **/
@Configuration(proxyBeanMethods = false)
public class SpOidcConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .antMatchers("/", "/index").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage(SpOidcApplication.getAuthorizationRequestURI())
                )
                .logout(oauth2Logout -> {
                    SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
                    logoutSuccessHandler.setUseReferer(true);
                    logoutSuccessHandler.setDefaultTargetUrl(SpOidcApplication.getAuthorizationRequestURI());
                    oauth2Logout.logoutSuccessHandler(logoutSuccessHandler);
                })
        ;
        return http.build();
    }

}
