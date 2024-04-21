package com.example.security.domain.member.application;

import com.example.security.domain.member.dto.request.MemberNicknameReq;
import com.example.security.domain.member.dto.request.MemberRegisterReq;
import com.example.security.domain.member.entity.Member;
import com.example.security.domain.member.entity.Privilege;
import com.example.security.domain.member.dao.MemberRepository;
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
    public void register(MemberRegisterReq registerReq) {
        // 회원가입 진행
        Member member = registerReq.toEntity();
        memberRepository.save(member);
    }

    @Override
    @Transactional
    public void updateNickname(MemberNicknameReq nicknameReq) {
        Member member = memberRepository.findByUsername(nicknameReq.username()).orElseThrow();
        member.modifyNickname(nicknameReq.nickname());
        System.out.println(member.getNickname());
        memberRepository.save(member);
    }
}
