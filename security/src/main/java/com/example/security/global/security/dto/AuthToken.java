package com.example.security.global.security.dto;

public record AuthToken(
        String accessToken,
        String refreshToken
) {
}
