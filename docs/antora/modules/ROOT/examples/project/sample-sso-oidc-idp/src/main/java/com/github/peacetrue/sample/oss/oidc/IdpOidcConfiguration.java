package com.github.peacetrue.sample.oss.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.MessageFormat;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.github.peacetrue.sample.oss.oidc.IdpOidcApplication.REGISTRATION_ID;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration.applyDefaultSecurity;

/**
 * @author xiayx
 * @since : 2021-07-21 07:21
 */
@Configuration(proxyBeanMethods = false)
//tag::import[]
//????????????????????????????????????????????????????????????
//@Import(OAuth2AuthorizationServerConfiguration.class) //<.>
//end::import[]
@EnableConfigurationProperties(IdpOidcProperties.class)
//tag::ClassStart[]
public class IdpOidcConfiguration {
    //end::ClassStart[]

    private IdpOidcProperties properties;

    public IdpOidcConfiguration(IdpOidcProperties properties) {
        this.properties = properties;
    }

    //tag::SecurityFilterChain[]

    /**
     * ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
     *
     * @see OAuth2AuthorizationServerConfiguration#authorizationServerSecurityFilterChain(HttpSecurity)
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        applyDefaultSecurity(http);
        return http
                // OAuth2AuthorizationServerConfiguration#authorizationServerSecurityFilterChain ?????? formLogin ?????????
                // ?????????????????????????????????????????????
                .formLogin(withDefaults())
                .build();
    }

    /**
     * ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
     * <b>????????????????????????????????????????????????????????? OAuth2 ??????????????????????????????????????????????????????????????????????????????</b>
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .formLogin(withDefaults())
                .build();
    }
    //end::SecurityFilterChain[]


    /**
     * ????????????????????????????????????UserDetailsServiceAutoConfiguration ??????????????????????????????????????????????????????
     *
     * @see UserDetailsServiceAutoConfiguration#inMemoryUserDetailsManager(SecurityProperties, ObjectProvider)
     */
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
                                                                 ObjectProvider<PasswordEncoder> passwordEncoder) {
        return new UserDetailsServiceAutoConfiguration().inMemoryUserDetailsManager(properties, passwordEncoder);
    }


    //tag::registeredClient[]

    /*?????????????????????*/


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(getRegisteredClients(properties.getSps()));
    }

    private static List<RegisteredClient> getRegisteredClients(List<IdpOidcProperties.Domain> clients) {
        return IntStream.range(0, clients.size())
                .mapToObj(serialNumber -> getRegisteredClient(serialNumber + 1, clients.get(serialNumber)))
                .collect(Collectors.toList());
    }

    private static RegisteredClient getRegisteredClient(Integer serialNumber, IdpOidcProperties.Domain domain) {
        //see OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI
        String clientAuthorizeEndpoint = "%s://%s:%s/%s/login/oauth2/code/%s";
        String clientId = getClientId(serialNumber);
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                //InMemoryRegisteredClientRepository ????????? secret ??????????????????
                .clientSecret("{noop}secret" + serialNumber)
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri(String.format(clientAuthorizeEndpoint,
                        domain.getProtocol(), domain.getHost(), domain.getPort(), clientId, REGISTRATION_ID))
                .scope(OidcScopes.OPENID)
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(false))
                .build();
    }

    private static String getClientId(int serialNumber) {
        return REGISTRATION_ID + "-" + serialNumber;
    }
    //end::registeredClient[]

    //tag::jwt[]

    /* ?????????????????? AccessToken ??? IdToken */

    @Bean
    public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRSAKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRSAKey() {
        KeyPair keyPair = generateRSAKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
    //end::jwt[]

    //tag::providerSettings[]

    @Bean
    public ProviderSettings providerSettings(@Value("${server.servlet.context-path}") String contextPath) {
        IdpOidcProperties.Domain idp = properties.getIdp();
        //???????????? issuer ???????????????????????????????????????
        return new ProviderSettings().issuer(String.format("%s://%s:%s%s",
                idp.getProtocol(), idp.getHost(), idp.getPort(), contextPath
        ));
    }
    //end::providerSettings[]


    //tag::ClassEnd[]

}
//end::ClassEnd[]
