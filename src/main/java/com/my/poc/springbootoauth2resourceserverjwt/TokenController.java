package com.my.poc.springbootoauth2resourceserverjwt;

import com.my.poc.springbootoauth2resourceserverjwt.security.CustomToken;
import com.my.poc.springbootoauth2resourceserverjwt.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/microservice-two")
@RequiredArgsConstructor
public class TokenController {

    private final TokenProvider tokenProvider;

    @GetMapping("/token")
    public ResponseEntity<CustomToken> getToken() {
        CustomToken token = tokenProvider.getToken();
        return ResponseEntity.ok(token);
    }
}
