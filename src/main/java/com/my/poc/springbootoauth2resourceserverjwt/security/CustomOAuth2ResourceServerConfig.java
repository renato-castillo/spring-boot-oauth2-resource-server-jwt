package com.my.poc.springbootoauth2resourceserverjwt.security;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
@EnableResourceServer
@Slf4j
public class CustomOAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Value("${jwt.signing.key}")
    private String jwtSigningKey;

    private final RequestMatcher requestMatcher = new AndRequestMatcher(
            new AntPathRequestMatcher("/api/**")
    );

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf().disable()
                .headers().httpStrictTransportSecurity().disable()
                .contentTypeOptions().disable()
                .and()
                .requestMatcher(requestMatcher)
                .authorizeRequests()
                .anyRequest()
                .authenticated();
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources
                .tokenServices(defaultTokenServices());
    }

    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        return new CustomJwtTokenConverter();
    }

    @Bean
    public DefaultTokenServices defaultTokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(jwtTokenStore());
        return defaultTokenServices;
    }

    @Bean
    public JwtClaimsSetVerifier jwtClaimsSetVerifier() {
        return new CustomJwtClaimsSetVerifier();
    }

    class CustomJwtClaimsSetVerifier implements JwtClaimsSetVerifier {

        @Override
        public void verify(Map<String, Object> claims) throws InvalidTokenException {
            Map<String, Object> authResponse = (LinkedHashMap) claims.get("auth_token");
            if(authResponse == null || authResponse.get("credentials") == null) {
                throw new InvalidTokenException("Invalid Jwt Token");
            }
        }
    }

    class CustomJwtTokenConverter extends JwtAccessTokenConverter {

        @SneakyThrows
        CustomJwtTokenConverter() {
            setSigningKey(jwtSigningKey);
            setVerifierKey(jwtSigningKey);
            setAccessTokenConverter(new DefaultAccessTokenConverter());
        }

        @Override
        public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
            OAuth2Authentication oAuth2Authentication = super.extractAuthentication(map);
            ExtractedJwtClaims extractedJwtClaims = new ExtractedJwtClaims();
            extractedJwtClaims.setAuthToken(map.get("auth_token"));
            extractedJwtClaims.setPermissions(map.get("permissions"));
            oAuth2Authentication.setDetails(extractedJwtClaims);
            return oAuth2Authentication;
        }
    }

    public class ExtractedJwtClaims {
        private Object authToken;
        private Object permissions;

        public Object getAuthToken() {
            return authToken;
        }

        public void setAuthToken(Object authToken) {
            this.authToken = authToken;
        }

        public Object getPermissions() {
            return permissions;
        }

        public void setPermissions(Object permissions) {
            this.permissions = permissions;
        }
    }
}
