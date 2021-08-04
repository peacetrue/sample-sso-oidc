package com.github.peacetrue.sample.oss.oidc;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author : xiayx
 * @since : 2021-07-29 09:33
 **/
//tag::ClassStart[]
@Configuration(proxyBeanMethods = false)
public class SpOidcConfiguration {
    //end::ClassStart[]

    //tag::SecurityFilterChain[]

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                //使用 oauth2 登录
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage(SpOidcApplication.getAuthorizationRequestURI())
                )
                .build();
    }
    //end::SecurityFilterChain[]

    //tag::ClassEnd[]

}
//end::ClassEnd[]
