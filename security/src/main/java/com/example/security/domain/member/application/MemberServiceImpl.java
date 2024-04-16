package com.example.security.domain.member.application;

import com.example.security.domain.member.dto.request.RegisterReq;
import com.example.security.domain.member.entity.Member;
import com.example.security.domain.member.entity.Privilege;
import com.example.security.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberServiceImpl implements MemberService{
    private final MemberRepository memberRepository;

    @Override
    @Transactional
    public void register(RegisterReq registerReq) {
        // 중복 체크
        Boolean isExist = memberRepository.existsByUsernameAndPassword(registerReq.username(), registerReq.password());
        if (isExist) { return ;}
        // 회원가입 진행
        Member member = Member.builder()
                .username(registerReq.username())
                .password(registerReq.password())
                .role(Privilege.USER)
                .build();
        memberRepository.save(member);
    }
}
