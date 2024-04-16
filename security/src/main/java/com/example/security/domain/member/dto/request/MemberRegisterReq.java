package com.example.security.domain.member.dto.request;

import com.example.security.domain.member.entity.Member;
import com.example.security.domain.member.entity.Privilege;

public record MemberRegisterReq(
        String username,
        String password
) {
    public Member toEntity() {
        return Member.builder()
                .username(this.username)
                .password(this.password)
                .role(Privilege.USER)
                .build();
    }
}
