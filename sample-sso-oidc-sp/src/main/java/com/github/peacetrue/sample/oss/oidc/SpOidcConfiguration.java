package com.github.peacetrue.sample.oss.oidc;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

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
                        oauth2Login.loginPage(SpOidcApplication.getAuthorizationRequestUri())
                )
        ;
        return http.build();
    }

}
