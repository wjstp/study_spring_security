package com.example.security.global.security.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenDTO(
        String accessToken,
        String refreshToken
) {
}
