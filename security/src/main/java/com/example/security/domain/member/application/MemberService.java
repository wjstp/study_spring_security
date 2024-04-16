package com.example.security.domain.member.application;

import com.example.security.domain.member.dto.request.JoinReq;

public interface MemberService {
    void join(JoinReq joinReq);
}
