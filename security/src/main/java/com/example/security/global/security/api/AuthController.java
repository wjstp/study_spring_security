package com.example.security.global.security.api;

import com.example.security.global.security.application.JwtService;
import com.example.security.global.security.dto.AuthToken;
import com.example.security.global.security.dto.TokenDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    JwtService jwtService;
    // 액세스 토큰 재발급
    @PostMapping("/refresh-token")
    public TokenDTO rotateRefreshToken(AuthToken authToken) {
         return jwtService.refreshAccessToken(authToken);
    }
}
