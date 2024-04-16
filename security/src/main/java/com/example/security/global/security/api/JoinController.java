package com.example.security.global.security.api;

import com.example.security.domain.member.dto.request.JoinReq;
import com.example.security.global.security.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {
    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(@RequestBody JoinReq joinReq) {
        joinService.joinProcess(joinReq);
        return "ok";
    }
}
