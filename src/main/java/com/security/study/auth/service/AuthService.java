package com.security.study.auth.service;

import com.security.study.auth.dao.AuthMapper;
import com.security.study.auth.dto.LoginDto;
import com.security.study.auth.dto.LoginUserDto;
import com.security.study.auth.dto.SignUpDto;
import com.security.study.auth.dto.TokenDto;
import com.security.study.config.advices.ApplicationException;
import com.security.study.config.advices.ErrorCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class AuthService implements UserDetailsService {
    private final AuthMapper authMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthService(
            AuthMapper authMapper,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider,
            AuthenticationManagerBuilder authenticationManagerBuilder
    ) {
        this.authMapper = authMapper;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    public Boolean checkEmail(String email) {
        return authMapper.checkEmail(email);
    }

    public void signUp(SignUpDto signUpDto) throws RuntimeException {
        if (checkEmail(signUpDto.getEmail())) {
            throw new ApplicationException(ErrorCode.DUPLICATED_USER_EMAIL);
        }

        //기본값 넣기
        signUpDto.setRole(2); //1: admin | 2: user
        signUpDto.setCreatedAt(LocalDateTime.now());

        //비밀번호 암호화
        signUpDto.setPassword(passwordEncoder.encode(signUpDto.getPassword()));

        authMapper.signUp(signUpDto);

    }

    public TokenDto login(LoginDto loginDto) throws RuntimeException {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());

        // loadUserByUsername 메소드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        return new TokenDto(
                jwtTokenProvider.generateAccessToken(authentication),
                jwtTokenProvider.generateRefreshToken()
        );
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return Optional.ofNullable(authMapper.getUserInfo(email))
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException("회원을 찾을 수 없습니다."));
    }

    private UserDetails createUserDetails(LoginUserDto user) {
//        List<Integer> roles = new ArrayList<>();
//        roles.add(user.getRole());
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), user.getPassword(), new ArrayList<>()
        );
    }
}


