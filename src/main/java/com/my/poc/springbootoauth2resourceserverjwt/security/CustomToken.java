package com.my.poc.springbootoauth2resourceserverjwt.security;

import lombok.Builder;
import lombok.Value;

import java.util.List;

@Value
@Builder
public class CustomToken {
    String userId;
    String bearerToken;
    List<String> permissionsList;
}
