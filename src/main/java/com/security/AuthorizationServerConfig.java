package com.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    
    /**
     * Configurando clients em memória utilizando os fluxos de autenticaçào password e refresh_token
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    .withClient("algafood-web")
                        .secret(passwordEncoder.encode("web123"))
                        .authorizedGrantTypes("password", "refresh_token")
                        .scopes("write", "read")
                        .accessTokenValiditySeconds(100)
                        .refreshTokenValiditySeconds(300)
                .and()
                    .withClient("api-hotpay")
                        .secret(passwordEncoder.encode("hotpay"))
                        .authorizedGrantTypes("client_credentials")
                        .scopes("read", "write")
                .and()
                    .withClient("marketplace")
                        .secret(passwordEncoder.encode("123"))
                        .authorizedGrantTypes("authorization_code")
                        .accessTokenValiditySeconds(15)
                        .scopes("read", "write")
                        .redirectUris("http://localhost:63341/authorization-code-client/index.html")
                .and()
                    .withClient("pkce-client")
                        .secret(passwordEncoder.encode("123"))
                        .authorizedGrantTypes("authorization_code")
                        .accessTokenValiditySeconds(15)
                        .scopes("read", "write")
                        .redirectUris("http://localhost:63341/authorization-code-pkce-client/index.html")
                .and()
                    .withClient("hub")
                        .authorizedGrantTypes("implicit")
                        .scopes("read", "write")
                        .redirectUris("http://aplicacao-cliente")
                
                .and()
                    .withClient("checktoken")
                        .secret(passwordEncoder.encode("check123"));
    }
    
    
    /**
     * Autorizar resource owners sem a necessidade de passar o client id e secret id nas chamadas
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
        security.checkTokenAccess("permitAll()");
    }
    
    /**
     * authenticationManager - Necessário para solicitações Password Flow
     * userDetailsService - Necessário para solitações Refresh Token
     * tokenGranter - Define os tipos de tokenGranter suportados. ex: passoword, client credentials, authorization code ...
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false)
                .tokenGranter(tokenGranter(endpoints));
    }
    
    /**
     * Necessário para suportar o tokenGranter do tipo authorization code que criamos de forma personalizada
     */
    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());
        
        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
        
        return new CompositeTokenGranter(granters);
    }
    
}
