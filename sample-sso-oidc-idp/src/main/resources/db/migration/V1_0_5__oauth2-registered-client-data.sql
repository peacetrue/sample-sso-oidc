INSERT INTO oauth2_registered_client (id, client_id, client_id_issued_at, client_secret,
                                               client_secret_expires_at, client_name, client_authentication_methods,
                                               authorization_grant_types, redirect_uris, scopes, client_settings,
                                               token_settings)
VALUES ('58675646-a391-4854-8bd3-09a16f37216f', 'oidc-sp-1', '2021-08-06 07:49:18', '{noop}secret1', null,
        '58675646-a391-4854-8bd3-09a16f37216f', 'post,basic', 'refresh_token,client_credentials,authorization_code',
        'http://127.0.0.1:9301/oidc-sp-1/login/oauth2/code/oidc-sp', 'openid',
        '{"@class":"java.util.HashMap","setting.client.require-user-consent":false,"setting.client.require-proof-key":false}',
        '{"@class":"java.util.HashMap","setting.token.access-token-time-to-live":["java.time.Duration",300.000000000],"setting.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"setting.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"setting.token.reuse-refresh-tokens":true}');


INSERT INTO oauth2_registered_client (id, client_id, client_id_issued_at, client_secret,
                                               client_secret_expires_at, client_name, client_authentication_methods,
                                               authorization_grant_types, redirect_uris, scopes, client_settings,
                                               token_settings)
VALUES ('58675646-a391-4854-8bd3-09a16f37216g', 'oidc-sp-2', '2021-08-06 07:49:18', '{noop}secret2', null,
        '58675646-a391-4854-8bd3-09a16f37216g', 'post,basic', 'refresh_token,client_credentials,authorization_code',
        'http://127.0.0.1:9302/oidc-sp-2/login/oauth2/code/oidc-sp', 'openid',
        '{"@class":"java.util.HashMap","setting.client.require-user-consent":false,"setting.client.require-proof-key":false}',
        '{"@class":"java.util.HashMap","setting.token.access-token-time-to-live":["java.time.Duration",300.000000000],"setting.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"setting.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"setting.token.reuse-refresh-tokens":true}');
