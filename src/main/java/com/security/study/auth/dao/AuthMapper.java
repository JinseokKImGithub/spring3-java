package com.security.study.auth.dao;

import com.security.study.auth.dto.LoginUserDto;
import com.security.study.auth.dto.SignUpDto;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AuthMapper {
    boolean checkEmail(String email);

    void signUp(SignUpDto signUpDto);
    LoginUserDto getUserInfo(String email);
}
