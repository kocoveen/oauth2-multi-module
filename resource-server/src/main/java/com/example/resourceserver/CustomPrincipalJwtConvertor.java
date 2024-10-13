package com.example.resourceserver;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class CustomPrincipalJwtConvertor implements Converter<Jwt, JwtAuthenticationToken> {


    @Override
    public JwtAuthenticationToken convert(Jwt source) {
        return new JwtAuthenticationToken(source);
    }
}
