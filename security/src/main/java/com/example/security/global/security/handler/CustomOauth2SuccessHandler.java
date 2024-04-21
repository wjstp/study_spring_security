package com.example.security.global.security.handler;

import com.example.security.global.security.application.JwtService;
import com.example.security.global.security.dto.CustomUserDetailsDTO;
import com.example.security.global.security.dto.OAuth2LoginDTO;
import com.example.security.global.security.filter.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomOauth2SuccessHandler implements AuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("로그인 성공");
        System.out.println(authentication.getPrincipal());
        System.out.println(authentication.getAuthorities());
        System.out.println(authentication.getDetails());
//        OAuth2LoginDTO customUserDetails = (OAuth2LoginDTO) authentication.getPrincipal();
        // access token 생성
        String accessToken = jwtUtil.generateAccessToken(authentication);
        response.addHeader("Authorization", "Bearer " + accessToken);

        // refresh token 발급
        String refreshToken = jwtUtil.generateRefreshToken(authentication);

        // refresh token 저장
        jwtService.saveToken(accessToken, refreshToken);
        Cookie cookie = jwtService.createCookie(refreshToken);
        response.addCookie(cookie);

        //로그인 성공 메세지
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"message\":\"로그인되었습니다.\"}");
    }
}
