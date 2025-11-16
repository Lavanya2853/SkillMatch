package com.skillmatch.controller;

import com.skillmatch.model.User;
import com.skillmatch.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/me")
    public ResponseEntity<?> me(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) return ResponseEntity.status(401).body("Unauthorized");
        String email = userDetails.getUsername();
        User user = userRepository.findByEmail(email).orElseThrow();
        user.setPassword(null); // hide password
        return ResponseEntity.ok(user);
    }
}
