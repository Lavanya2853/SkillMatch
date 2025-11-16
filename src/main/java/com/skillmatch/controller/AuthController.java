package com.skillmatch.controller;

import com.skillmatch.dto.auth.*;
import com.skillmatch.model.User;
import com.skillmatch.security.JwtService;
import com.skillmatch.service.auth.UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    // -------------------------
    // REGISTER
    // -------------------------
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {

        userService.registerUser(request);

        AuthResponse response = new AuthResponse(null, "User registered successfully");
        return ResponseEntity.ok(response);
    }

    // -------------------------
    // LOGIN
    // -------------------------
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest login) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        login.getEmail(),
                        login.getPassword()
                )
        );

        String access = jwtService.generateAccessToken(login.getEmail());
        String refresh = jwtService.generateRefreshToken(login.getEmail());

        // TokenResponse: accessToken + refreshToken + role
        return ResponseEntity.ok(new TokenResponse(access, refresh, "USER"));
    }

    // -------------------------
    // REFRESH (Legacy version)
    // -------------------------
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest req) {

        String refreshToken = req.getRefreshToken();

        if (!jwtService.validateToken(refreshToken)) {
            return ResponseEntity.badRequest().body("Invalid refresh token");
        }

        String email = jwtService.extractSubject(refreshToken);
        String newAccess = jwtService.generateAccessToken(email);

        return ResponseEntity.ok(new TokenResponse(newAccess, refreshToken, "USER"));
    }

    // -------------------------
    // REFRESH TOKEN (Modern version)
    // -------------------------
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {

        String refreshToken = request.getRefreshToken();

        if (!jwtService.isTokenValid(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid or expired refresh token"));
        }

        String email = jwtService.extractUsername(refreshToken);
        String newAccess = jwtService.generateAccessToken(email);

        return ResponseEntity.ok(Map.of(
                "accessToken", newAccess
        ));
    }
}
