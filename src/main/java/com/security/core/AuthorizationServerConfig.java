package com.security.core;

import com.security.core.mfa.MfaService;
import com.security.core.mfa.MfaTokenGranter;
import com.security.core.mfa.PasswordTokenGranter;
import com.security.core.user.JwtCustomClaimsTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
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
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

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
    
    @Autowired
    private JwtKeyStoreProperties jwtKeyStoreProperties;
    
    @Autowired
    private MfaService mfaService;
    
    /**
     * Configurando clients em memória utilizando os fluxos de autenticaçào password e refresh_token
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    .withClient("algafood-web")
                        .secret(passwordEncoder.encode("web123"))
                        .authorizedGrantTypes("password", "refresh_token", "mfa")
                        .scopes("write", "read")
                        .accessTokenValiditySeconds(100)
                        .refreshTokenValiditySeconds(300)
                .and()
                    .withClient("api-hotpay")
                        .secret(passwordEncoder.encode("hotpay"))
                        .authorizedGrantTypes("client_credentials")
                        .scopes("read")
                .and()
                    .withClient("marketplace")
                        .secret(passwordEncoder.encode("123"))
                        .authorizedGrantTypes("authorization_code")
                        .accessTokenValiditySeconds(200)
                        .scopes("read", "write")
                        .redirectUris("http://localhost:63341/authorization-code-client/index.html")
                .and()
                    .withClient("pkce-client")
                        .secret(passwordEncoder.encode(""))
                        .authorizedGrantTypes("authorization_code")
                        .accessTokenValiditySeconds(200)
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
     * checkTokenAccess("permitAll()") - Autorizar resource owners sem a necessidade de passar o client id e secret id nas chamadas
     * allowFormAuthenticationForClients - Permite passar as credenciais (client id e secret id) do cliente no body da requisicao
     * tokenKeyAccess("permitAll()") - Libera o endpoint /oauth/token_key para obter a chave publica usado no alg assimétrico para geraçao do JWT
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
        security.checkTokenAccess("permitAll()")
                .tokenKeyAccess("permitAll()")
                .allowFormAuthenticationForClients();
    }
    
    /**
     * authenticationManager - Necessário para solicitações Password Flow
     * userDetailsService - Necessário para solitações Refresh Token
     * tokenGranter - Define os tipos de tokenGranter suportados. ex: passoword, client credentials, authorization code ...
     * accessTokenConverter - Necessário para converter o token do usuário em um token transparente JWT
     * approvalStore - Necessário para renderizar uma autorização granular de escopos ao usar o fluxo de authorization code
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        var enhancerChain = new TokenEnhancerChain();
        enhancerChain.setTokenEnhancers(
                Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter())
        );
        
        endpoints
                /*Linha comentda para não utilizar o Password Flow padrão do oauth2 e usar o PasswordTokenGranter criado no pacote mfa do projeto*/
                /*.authenticationManager(authenticationManager)*/
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false)
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenEnhancer(enhancerChain)
                .approvalStore(approvalStore(endpoints.getTokenStore()))
                .tokenGranter(tokenGranter(endpoints));
    }
    
    private ApprovalStore approvalStore(TokenStore tokenStore) {
        var approvalStore = new TokenApprovalStore();
        approvalStore.setTokenStore(tokenStore);
        return approvalStore;
    }
    
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        var jwtAccessTokenConverter = new JwtAccessTokenConverter();
        var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
        var keyStorePass = jwtKeyStoreProperties.getPassword();
        var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
        var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
        var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
        jwtAccessTokenConverter.setKeyPair(keyPair);
        return jwtAccessTokenConverter;
    }
    
    /**
     * Necessário para suportar o tokenGranter do tipo authorization code que criamos de forma personalizada
     */
    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter =
                new PkceAuthorizationCodeTokenGranter(
                        endpoints.getTokenServices(),
                        endpoints.getAuthorizationCodeServices(),
                        endpoints.getClientDetailsService(),
                        endpoints.getOAuth2RequestFactory()
                );
    
        var passwordTokenGranter = new PasswordTokenGranter(endpoints, authenticationManager, mfaService);
        var mfaTokenGranter = new MfaTokenGranter(endpoints, mfaService, userDetailsService);
        
        var granters = Arrays.asList(
                passwordTokenGranter,
                mfaTokenGranter,
                pkceAuthorizationCodeTokenGranter,
                endpoints.getTokenGranter());
        
        return new CompositeTokenGranter(granters);
    }
    
}
