package com.github.peacetrue.sample.oss.oidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

/**
 * @author : xiayx
 * @since : 2021-07-21 07:21
 **/
@SpringBootApplication
public class SpOidcApplication {

    static final String REGISTRATION_ID = "oidc-sp";

    static String getAuthorizationRequestUri() {
        return String.format("%s/%s", DEFAULT_AUTHORIZATION_REQUEST_BASE_URI, REGISTRATION_ID);
    }

    public static void main(String[] args) {
        SpringApplication.run(SpOidcApplication.class, args);
    }
}
