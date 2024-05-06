package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.DTO.AuthenticationRequest;
import com.example.springsecurityjwt.DTO.UserDto;
import com.example.springsecurityjwt.service.AuthService;
import com.example.springsecurityjwt.service.impl.AuthenticationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody UserDto userdto){
        AuthenticationResponse authResponse = authService.register(userdto);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
            return ResponseEntity.ok(authService.authenticate(request));
    }
}
