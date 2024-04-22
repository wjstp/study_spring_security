package com.example.security.global.security.filter;

import com.example.security.global.security.application.JwtService;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
//요청에 대해 한번만 작동하는 필터 onceperrequestfilter
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @Nonnull FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = jwtService.authenticateJwtToken(request);
        // 세션에 사용자 등록 - securitycontextholder에 등록한다.
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // 그 다음 필터로 이동
        filterChain.doFilter(request, response);
        // 예외 처리 추가
        System.out.println("토큰 검증 완료");
    }
}
