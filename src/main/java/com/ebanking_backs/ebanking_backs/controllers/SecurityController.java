package com.ebanking_backs.ebanking_backs.controllers;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
// import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class SecurityController {


    @Autowired
    private AuthenticationManager authenticationManager;
   

    @Autowired
    private JwtEncoder jwtEncoder;


    @GetMapping("/profile")
    public Authentication authentication(Authentication authentication) {
        return authentication;
    }

    @PostMapping("/login")
    public Map<String, String> login(String username, String password) {
      Authentication authentication =  authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

      Instant instant = Instant.now();
     String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
      JwtClaimsSet claimsSet = JwtClaimsSet.builder()
      .issuedAt(instant)
      .expiresAt(instant.plusSeconds(3600))
      .subject(username)
      .claim("scope", scope)
      .build();

      JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(
        JwsHeader.with(MacAlgorithm.HS256).build(), 
        claimsSet);
    String jwt = jwtEncoder.encode(jwtEncoderParameters).getTokenValue();

    return Map.of("access_token", jwt);
      

        
    }

}
