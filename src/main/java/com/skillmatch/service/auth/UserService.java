package com.skillmatch.service.auth;

import com.skillmatch.dto.auth.RegisterRequest;
import com.skillmatch.model.User;

public interface UserService {
    User registerUser(RegisterRequest request);
    User getUserByEmail(String email);
}
