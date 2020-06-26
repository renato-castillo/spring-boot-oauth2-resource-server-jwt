package com.my.poc.springbootoauth2resourceserverjwt.security;

import com.my.poc.springbootoauth2resourceserverjwt.security.CustomOAuth2ResourceServerConfig.ExtractedJwtClaims;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class CustomTokenProvider implements TokenProvider {

    @Override
    public CustomToken getToken() {
        OAuth2AuthenticationDetails oAuth2Authentication =
                (OAuth2AuthenticationDetails) SecurityContextHolder.getContext().getAuthentication().getDetails();
        ExtractedJwtClaims decodedDetails = (ExtractedJwtClaims) oAuth2Authentication.getDecodedDetails();
        Map<String, ?> authResponse = (LinkedHashMap) decodedDetails.getAuthToken();
        Map<String, ?> permissions = (LinkedHashMap) decodedDetails.getPermissions();
        String bearerToken = authResponse.get("credentials").toString();
        ArrayList permissionsList = (ArrayList) permissions.get("permissions");
        ArrayList permList = (ArrayList) permissionsList.stream().collect(Collectors.toList());

        return CustomToken.builder()
                .bearerToken(bearerToken)
                .permissionsList(permList)
                .build();
    }
}
