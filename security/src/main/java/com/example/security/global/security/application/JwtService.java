package com.example.security.global.security.application;

import com.example.security.domain.member.entity.Member;
import com.example.security.domain.member.entity.Privilege;
import com.example.security.global.security.dto.AuthToken;
import com.example.security.global.security.dto.CustomUserDetailsDTO;
import com.example.security.global.security.dto.TokenDTO;
import com.example.security.global.security.filter.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtUtil jwtUtil;
    private static final String ACCESS_HEADER_AUTHORIZATION = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";

    public Authentication authenticateJwtToken(HttpServletRequest request) {
        String token = parseJwt(request);
        if (Objects.isNull(token)) {
            return null;
        }
        Claims claims = verifyJwtToken(token);
        String username = claims.get("username").toString();
        String role = claims.get("role").toString();   // 수정
        // member를 생성하여 값 set

        CustomUserDetailsDTO customUserDetails = CustomUserDetailsDTO.builder()
                .username(username)
                .role(Privilege.valueOf(role))
                .build();
        // 스프링 시큐리티 인증 토큰 생성
        return new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
    }


    public String parseJwt(HttpServletRequest request) {
        // request에서 Authorization헤더를 찾음
        String authorization = request.getHeader(ACCESS_HEADER_AUTHORIZATION);

        // Authorization 헤더 검증
        if (Objects.isNull(authorization)){
            System.out.println("토큰이 존재하지 않습니다.");
            return null;
        }
        if(!authorization.startsWith(TOKEN_PREFIX)) {
            System.out.println("접두사가 일치하지 않습니다.");
            return null;
        }
        // Bearer 제거 후 순수 토큰 획득
        return authorization.split(" ")[1];
    }

    // token 갱신
    public TokenDTO refreshAccessToken(AuthToken authToken) {
        Claims claims = verifyJwtToken(authToken.refreshToken()); // 예외처리 할 것


        CustomUserDetailsDTO userDetailsDTO = CustomUserDetailsDTO.builder()
                .username(claims.get("username").toString())
                .role(Privilege.valueOf((String) claims.get("role")))
                .build();
        // access token 발급
        String accessToken = jwtUtil.generateAccessToken(userDetailsDTO);
        // refresh token 갱신
        String newRefreshToken = jwtUtil.generateRefreshToken(accessToken, userDetailsDTO);

        return new TokenDTO(accessToken, newRefreshToken);
    }


    public Claims verifyJwtToken(String token) {
        System.out.println("토큰 검증 시작");
        try {
            return jwtUtil.verifyJwtToken(token);
        } catch(MalformedJwtException malformedJwtException) {
            throw new RuntimeException("Malformed Token");
        }
    }
}
