package com.example.security.domain.member.application;

import com.example.security.domain.member.dto.request.RegisterReq;

public interface MemberService {
    void register(RegisterReq registerReq);
}
