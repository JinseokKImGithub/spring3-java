package com.security.study.auth.controller;

import com.security.study.auth.dto.LoginDto;
import com.security.study.auth.dto.SignUpDto;
import com.security.study.auth.dto.TokenDto;
import com.security.study.auth.service.AuthService;
import com.security.study.config.advices.ApplicationException;
import com.security.study.config.advices.ErrorCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public TokenDto login(@RequestBody LoginDto loginDto) {
        try {
            System.out.println("email : " + loginDto.getEmail());
            System.out.println("password : " + loginDto.getPassword());
            return authService.login(loginDto);
        } catch (Exception e) {
            throw new ApplicationException(ErrorCode.LOGIN_ERROR);
        }
    }

    @PostMapping("/sign-up")
    public void signUp(@RequestBody SignUpDto signUpDto) {
        authService.signUp(signUpDto);
    }

    @GetMapping("/check-email")
    public Boolean checkEmail(@RequestParam String email) {
        return authService.checkEmail(email);
    }

}
