package com.example.security.domain.member.application;

import com.example.security.domain.member.dto.request.MemberRegisterReq;

public interface MemberService {

    void register(MemberRegisterReq registerReq);
}
