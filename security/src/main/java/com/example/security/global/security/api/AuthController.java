package com.example.security.global.security.api;

import com.example.security.global.security.application.JwtService;
import com.example.security.global.security.dto.AuthToken;
import com.example.security.global.security.dto.TokenDTO;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Objects;

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController {
    private final JwtService jwtService;
    // 액세스 토큰 재발급
    @PostMapping( "/auth/refresh")
    public void rotateRefreshToken(HttpServletRequest request, HttpServletResponse response,
                                   @RequestBody AuthToken authToken) {
        log.info("토큰 재발급 시작");
        String refreshToken = this.getCookie(request).getValue();
        log.info(refreshToken);
        String accessToken = authToken.accessToken();
        log.info("액세스 토큰 " + accessToken);
        TokenDTO tokenDTO = jwtService.refreshAccessToken(refreshToken, accessToken);
        // accessToken 헤더에 추가
        response.addHeader("Access-Token", "Bearer " + tokenDTO.accessToken());
        // 새로운 리프레시 토큰이 담긴 쿠키 헤더에 추가
        Cookie cookie = jwtService.createCookie(tokenDTO.refreshToken());
        response.addCookie(cookie);
    }

    private Cookie getCookie(HttpServletRequest request) {
        log.info(Objects.toString(request) + "쿠키");
        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals("Refresh-Token"))
                .findFirst()
                .orElseThrow(()-> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Refresh token cookie expired"));
    }
}
