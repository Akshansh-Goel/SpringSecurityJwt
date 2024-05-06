package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.DTO.AuthenticationRequest;
import com.example.springsecurityjwt.DTO.UserDto;
import com.example.springsecurityjwt.service.impl.AuthenticationResponse;
import org.springframework.http.ResponseEntity;

public interface AuthService {

    AuthenticationResponse register(UserDto userDto);

    AuthenticationResponse authenticate(AuthenticationRequest request);
}
