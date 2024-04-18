package com.example.security.global.security.application;

import org.springframework.stereotype.Service;

@Service
public class TokenRedisService {
    // access token, refresh token 발급시 토큰 저장

    // access token 만료 시 refresh token 확인 후 access token 재발급
    // refresh token 만료 시 회원 정보 확인 후 refresh token, access token 재발급
}
