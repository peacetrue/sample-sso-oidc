package com.github.peacetrue.sample.oss.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.h2.H2ConsoleProperties;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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


    //tag::registeredClient[]

    /**
     * ????????????????????????
     */
    @Profile("db")
    @Configuration(proxyBeanMethods = false)
    public static class DBConfiguration {

        @Bean
        public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
            return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        }

        @Bean
        public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
            return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
        }

        @Bean
        public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
            return new JdbcRegisteredClientRepository(jdbcTemplate);
        }

        @Autowired
        public void initUserDetailsManager(AuthenticationManagerBuilder builder, DataSource dataSource) throws Exception {
            builder.jdbcAuthentication().dataSource(dataSource);
        }

        @Bean
        @ConditionalOnMissingBean
        public PasswordEncoder passwordEncoder() {
            return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }

        /**
         * ???????????????????????????????????????????????????????????????????????????????????????
         * <p>
         * ??????????????????????????????
         * <ul>
         *     <li>/db/migration/V1_0_4__users-data.sql</li>
         *     <li>/db/migration/V1_0_5__oauth2-registered-client-data.sql</li>
         * </ul>
         */
        //@Configuration(proxyBeanMethods = false)
        public static class DataInitConfiguration {

            @Autowired
            public void initRegisteredClient(RegisteredClientRepository repository, IdpOidcProperties properties) {
                List<IdpOidcProperties.Domain> sps = properties.getSps();
                IntStream.range(0, sps.size()).forEach(serialNumber -> {
                    RegisteredClient registeredClient = repository.findByClientId(getClientId(serialNumber));
                    if (registeredClient == null) {
                        repository.save(getRegisteredClient(serialNumber + 1, sps.get(serialNumber)));
                    }
                });
            }

            @Autowired
            public void initUserDetails(UserDetailsManager userDetailsManager,
                                        PasswordEncoder passwordEncoder,
                                        SecurityProperties properties) {
                SecurityProperties.User user = properties.getUser();
                userDetailsManager.createUser(User.withUsername(user.getName())
                        .password(passwordEncoder.encode(user.getPassword()))
                        .roles(user.getRoles().toArray(new String[0])).build());
            }

        }

        /**
         * ?????? H2 ???????????????
         */
        @Profile("h2")
        @Configuration(proxyBeanMethods = false)
        public static class MemoryConfiguration {
            @Bean
            public EmbeddedDatabase embeddedDatabase() {
                // @formatter:off
                return new EmbeddedDatabaseBuilder()
                        .setType(EmbeddedDatabaseType.H2)
                        .build();
                // @formatter:on
            }

            @Bean
            public WebSecurityCustomizer ignoringH2Console(H2ConsoleProperties properties) {
                return web -> web
                        .ignoring()
                        .antMatchers(properties.getPath() + "/**")
                        ;
            }
        }
    }

    /**
     * ?????????????????????
     */
    @Profile("memory")
    @Configuration(proxyBeanMethods = false)
    public static class MemoryConfiguration {

        @Bean
        public RegisteredClientRepository registeredClientRepository(IdpOidcProperties properties) {
            return new InMemoryRegisteredClientRepository(getRegisteredClients(properties.getSps()));
        }

        private static List<RegisteredClient> getRegisteredClients(List<IdpOidcProperties.Domain> clients) {
            return IntStream.range(0, clients.size())
                    .mapToObj(serialNumber -> getRegisteredClient(serialNumber + 1, clients.get(serialNumber)))
                    .collect(Collectors.toList());
        }

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
