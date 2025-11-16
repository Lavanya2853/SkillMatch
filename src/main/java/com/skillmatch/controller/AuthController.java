package com.skillmatch.controller;

import com.skillmatch.dto.auth.*;
import com.skillmatch.model.User;
import com.skillmatch.service.auth.UserService;
import com.skillmatch.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        User user = userService.registerUser(request);
        return ResponseEntity.ok(new AuthResponse(null, "User registered successfully!"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest login) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(login.getEmail(), login.getPassword())
        );

        // Fetch the full user to get the role
        User user = userService.getUserByEmail(login.getEmail());

        String access = jwtService.generateAccessToken(login.getEmail());
        String refresh = jwtService.generateRefreshToken(login.getEmail());

        return ResponseEntity.ok(
                new TokenResponse(access, refresh, user.getRole())
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest req) {
        String refreshToken = req.getRefreshToken();

        if (refreshToken == null || !jwtService.validateToken(refreshToken)) {
            return ResponseEntity.badRequest().body("Invalid refresh token");
        }

        String email = jwtService.extractSubject(refreshToken);

        User user = userService.getUserByEmail(email);

        String newAccess = jwtService.generateAccessToken(email);

        return ResponseEntity.ok(
                new TokenResponse(newAccess, refreshToken, user.getRole())
        );
    }
}
