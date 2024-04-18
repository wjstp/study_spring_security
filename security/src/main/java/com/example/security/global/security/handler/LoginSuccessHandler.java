package com.example.security.global.security.handler;

import com.example.security.global.security.dto.CustomUserDetailsDTO;
import com.example.security.global.security.filter.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        CustomUserDetailsDTO customUserDetails = (CustomUserDetailsDTO) authentication.getPrincipal();
        // access token 생성
        String accessToken = jwtUtil.generateAccessToken(customUserDetails);
        response.addHeader("Authorization", "Bearer " + accessToken);
        // refresh token 발급
        String refreshToken = jwtUtil.generateRefreshToken(accessToken, customUserDetails);
        Cookie cookie = createCookie(refreshToken);
        response.addCookie(cookie);

        //로그인 성공 메세지
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"message\":\"로그인되었습니다.\"}");
    }


    public Cookie createCookie(String refreshToken) {
        String cookieName = "Refresh-Token";
        Cookie cookie = new Cookie(cookieName, refreshToken);
        // 쿠키 속성 설정
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/auth/refresh");
        cookie.setMaxAge(15&50*60*24);
        return cookie;
    }
}
