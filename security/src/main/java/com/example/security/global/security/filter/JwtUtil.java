package com.example.security.global.security.filter;

import com.example.security.global.security.dao.RefreshTokenRepository;
import com.example.security.global.security.dto.CustomUserDetailsDTO;
import com.example.security.global.security.dto.RefreshToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@Component
public class JwtUtil {
    private final SecretKey secretKey;
    private final long accessTokenExpiration;
    private final long refreshTokenExpiration;

    private RefreshTokenRepository refreshTokenRepository;

    public JwtUtil (
            @Value("${spring.jwt.secret}")
            SecretKey secretKey,
            @Value("${spring.jwt.secret.expiration")
            long accessTokenExpiration,
            @Value("${spring.jwt.refresh-token.expiration")
            long refreshTokenExpiration
    ) {
        this.secretKey = secretKey;
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    // 토큰 검증
    public Claims verifyJwtToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    // access token  생성
    public String generateAccessToken(CustomUserDetailsDTO customUserDetailsDTO) {
        // username
        String username = customUserDetailsDTO.getUsername();
        // role
        Collection<? extends GrantedAuthority> authorities = customUserDetailsDTO.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();
        return createToken(username, role, accessTokenExpiration);
    }

    // refresh token 생성
    public String generateRefreshToken(String accessToken, CustomUserDetailsDTO customUserDetailsDTO) {
        // username
        String username = customUserDetailsDTO.getUsername();
        // role
        Collection<? extends GrantedAuthority> authorities = customUserDetailsDTO.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();
        String refreshToken = createToken(username, role, refreshTokenExpiration);
        // redis에 저장
        // 기존에 이미
        saveToken(refreshToken, accessToken);
        return refreshToken;
    }
    // 토큰 생성
    public String createToken(String username, String role, long expiration) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(secretKey)
                .compact();
    }
    // token 저장
    public void saveToken(String accessToken, String refreshToken) {
        refreshTokenRepository.save(
                RefreshToken.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build()
        );
    }
}
