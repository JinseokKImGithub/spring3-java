package com.security.study.config.auth;

import com.security.study.auth.service.JwtTokenProvider;
import com.security.study.config.advices.ApplicationException;
import com.security.study.config.advices.ErrorCode;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


public class JwtFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    public JwtFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException, RuntimeException {
        try {
            //토큰 추출
            String extractedToken = extractToken(request);
            if (extractedToken != null && jwtTokenProvider.validateToken(extractedToken)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(extractedToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                request.setAttribute("X-Authorization-Id", authentication.getName());
                System.out.println("👀if (extractedToken != null && jwtTokenProvider.validateToken(extractedToken))");


            }

            filterChain.doFilter(request, response);

        }catch (ExpiredJwtException e){
            //토큰의 유효기간 만료
            throw new ApplicationException(ErrorCode.TOKEN_EXPIRED);
        }catch (JwtException | IllegalArgumentException e){
            //유효하지 않은 토큰
            throw new ApplicationException(ErrorCode.INVALID_TOKEN);
        }
    }

    // Request Header 에서 토큰 정보 추출
    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
