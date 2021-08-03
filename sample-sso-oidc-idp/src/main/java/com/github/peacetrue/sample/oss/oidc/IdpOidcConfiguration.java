package com.github.peacetrue.sample.oss.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
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
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration.applyDefaultSecurity;

/**
 * @author xiayx
 * @since : 2021-07-21 07:21
 */
@Configuration(proxyBeanMethods = false)
//tag::import[]
//类库提供的配置无法直接使用
//@Import(OAuth2AuthorizationServerConfiguration.class) //<.>
//end::import[]

//tag::class-start[]
public class IdpOidcConfiguration {
    //end::class-start[]

    //tag::SecurityFilterChain[]

    /**
     * 认证服务端安全拦截器链，所有认证服务端的功能都在此链中实现，包括授权码端点、访问令牌端点等等
     *
     * @see OAuth2AuthorizationServerConfiguration#authorizationServerSecurityFilterChain(HttpSecurity)
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        applyDefaultSecurity(http);
        return http
                // OAuth2AuthorizationServerConfiguration#authorizationServerSecurityFilterChain 缺少 formLogin 配置，
                // 导致未登录时无法重定向回登录页
                .formLogin(withDefaults())
                .build();
    }

    /**
     * 默认的安全拦截器链，此链优先级低于认证服务端安全拦截器链，用于实现应用自身的安全功能。
     * <b>注意：认证服务端安全拦截器链专注于实现 OAuth2 相关的认证功能，并不包含基础的登录认证，此链是必须的</b>
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
     * 因为在认证服务端环境下，UserDetailsServiceAutoConfiguration 的自动配置条件失效，所以需要重新声明
     *
     * @see UserDetailsServiceAutoConfiguration#inMemoryUserDetailsManager(SecurityProperties, ObjectProvider)
     */
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
                                                                 ObjectProvider<PasswordEncoder> passwordEncoder) {
        return new UserDetailsServiceAutoConfiguration().inMemoryUserDetailsManager(properties, passwordEncoder);
    }


    //tag::registeredClient[]

    /*基于内存的配置*/

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(getRegisteredClients());
    }

    private static List<RegisteredClient> getRegisteredClients() {
        return IntStream.rangeClosed(1, 2)
                .mapToObj(IdpOidcConfiguration::getRegisteredClient)
                .collect(Collectors.toList());
    }

    private static String getClientId(int serialNumber) {
        return "oidc-sp-" + serialNumber;
    }

    private static RegisteredClient getRegisteredClient(Integer serialNumber) {
        //see OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI
        String clientAuthorizeEndpoint = "http://127.0.0.1:930{0}/{1}/login/oauth2/code/{2}";
        String clientId = getClientId(serialNumber);
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                //InMemoryRegisteredClientRepository 中要求 secret 不能重复，坑
                .clientSecret("{noop}secret" + serialNumber)
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri(MessageFormat.format(clientAuthorizeEndpoint, serialNumber, clientId, "oidc-sp"))
                .scope(OidcScopes.OPENID)
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(false))
                .build();
    }
    //end::registeredClient[]

    //tag::jwt[]

    /* 加密解密 AccessToken 和 IdToken 需要 */

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

    @Bean
    public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    //end::jwt[]

    //tag::providerSettings[]

    @Bean
    public ProviderSettings providerSettings(ServerProperties properties, @Value("${server.host}") String host) {
        return new ProviderSettings().issuer(MessageFormat.format("http://{0}:{1}{2}",
                host, String.valueOf(properties.getPort()),
                Objects.toString(properties.getServlet().getContextPath(), "")
        ));
    }
    //end::providerSettings[]


    //tag::class-end[]

}
//end::class-end[]
