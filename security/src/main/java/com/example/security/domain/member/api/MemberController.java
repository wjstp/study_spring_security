package com.example.security.domain.member.api;

import com.example.security.domain.member.application.MemberService;
import com.example.security.domain.member.dto.request.MemberNicknameReq;
import com.example.security.domain.member.dto.request.MemberRegisterReq;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/register")
    public String register(@RequestBody MemberRegisterReq registerReq) {
        memberService.register(registerReq);
        return "ok";
    }

    @PatchMapping("/nickname")
    public String modifyNickname(@RequestBody MemberNicknameReq nicknameReq) {
        memberService.updateNickname(nicknameReq);
        return "modify success";
    }
}
