package com.security.study.auth.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class SignUpDto {
    private String email;
    private String password;
    private String name;
    private String gender;
    private String phoneNumber;
    private int role;
    private LocalDateTime createdAt;
}
