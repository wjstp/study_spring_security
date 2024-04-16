package com.example.security.domain.member.application;

import com.example.security.domain.member.dto.request.JoinReq;
import com.example.security.domain.member.entity.Member;
import com.example.security.domain.member.entity.Privilege;
import com.example.security.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService{
    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void join(JoinReq joinReq) {
        Boolean isExist = memberRepository.existsByUsernameAndPassword(joinReq.username(), joinReq.password());
        if (isExist) {
            return ;
        }
        // 회원가입 진행
        Member member = Member.builder()
                .username(joinReq.username())
                .password(bCryptPasswordEncoder.encode(joinReq.password()))
                .role(Privilege.ADMIN)
                .build();
        // 비밀번호는 bcryptencoder를 통해 암호화
        memberRepository.save(member);
    }
}
