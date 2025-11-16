package com.skillmatch.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtService {

    private final Key key;

    @Value("${jwt.accessExpirationMs}")
    private long accessExpiryMs;

    @Value("${jwt.refreshExpirationMs}")
    private long refreshExpiryMs;

    public JwtService(@Value("${jwt.secret}") String secret) {
        // expect secret in base64 or plain; decode safely by using bytes
        byte[] keyBytes = secret.getBytes(); // simple approach for dev
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(String subject) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + accessExpiryMs);
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(String subject) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + refreshExpiryMs);
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    public String extractSubject(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        return claims.getSubject();
    }
}
