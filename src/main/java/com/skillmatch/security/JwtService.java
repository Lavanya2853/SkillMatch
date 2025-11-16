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
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    // -------------------------
    // ACCESS TOKEN
    // -------------------------
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

    // -------------------------
    // REFRESH TOKEN
    // -------------------------
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


    // -------------------------
    // VALIDATE TOKEN
    // -------------------------
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;

        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // -------------------------
    // EXTRACT SUBJECT / EMAIL
    // -------------------------
    public String extractSubject(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // -------------------------
    // MATCHING METHODS NEEDED BY CONTROLLER
    // -------------------------
    public boolean isTokenValid(String token) {
        return validateToken(token);
    }

    public String extractUsername(String token) {
        return extractSubject(token);
    }
}
