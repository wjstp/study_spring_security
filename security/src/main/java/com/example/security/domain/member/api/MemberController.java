package com.example.security.domain.member.api;

import com.example.security.domain.member.application.MemberService;
import com.example.security.domain.member.dto.request.RegisterReq;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/register")
    public String register(@RequestBody RegisterReq registerReq) {
        memberService.register(registerReq);
        return "ok";
    }
}
