package com.github.peacetrue.sample.oss.oidc;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "peacetrue.idp-oidc")
public class IdpOidcProperties {

    @Data
    public static class Domain {
        private String protocol;
        private String host;
        private int port;
    }

    private Domain idp = new Domain();
    private Domain sp = new Domain();
    private List<Domain> sps = Collections.emptyList();

}
