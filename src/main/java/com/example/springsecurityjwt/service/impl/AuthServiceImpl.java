package com.example.springsecurityjwt.service.impl;

import com.example.springsecurityjwt.DTO.AuthenticationRequest;
import com.example.springsecurityjwt.DTO.UserDto;
import com.example.springsecurityjwt.config.JwtService;
import com.example.springsecurityjwt.repository.UserRepository;
import com.example.springsecurityjwt.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import com.example.springsecurityjwt.entity.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserRepository repository;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthServiceImpl(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
    @Override
    public AuthenticationResponse register(UserDto dto) {

        User user = new User(dto.getFirstname(),dto.getLastname(),dto.getEmail(), encoder.encode(dto.getPassword()),dto.getRole());
        var savedUser=repository.save(user);
        String token = jwtService.generateToken(user);
        AuthenticationResponse res = new AuthenticationResponse();
        res.setAccessToken(token);
        return res;


    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        String token = jwtService.generateToken(user);
        AuthenticationResponse res = new AuthenticationResponse();
        res.setAccessToken(token);
        return res;
    }
}
