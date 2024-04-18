package com.example.security.global.security.handler;

import com.example.security.global.security.dto.CustomUserDetailsDTO;
import com.example.security.global.security.filter.JwtUtil;
import jakarta.servlet.ServletException;
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
        // token 생성
        String token = jwtUtil.generateAccessToken(customUserDetails);
        response.addHeader("Authorization", "Bearer " + token);
    }
}
