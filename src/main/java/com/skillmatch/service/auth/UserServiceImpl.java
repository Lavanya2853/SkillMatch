package com.skillmatch.service.auth;

import com.skillmatch.dto.auth.RegisterRequest;
import com.skillmatch.model.User;
import com.skillmatch.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User registerUser(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered!");
        }
        User u = new User();
        u.setFullName(request.getFullName());
        u.setEmail(request.getEmail());
        u.setBio(request.getBio());
        u.setLocation(request.getLocation());
        u.setRole("USER");
        u.setPassword(passwordEncoder.encode(request.getPassword()));
        return userRepository.save(u);
    }

    @Override
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow();
    }
}
