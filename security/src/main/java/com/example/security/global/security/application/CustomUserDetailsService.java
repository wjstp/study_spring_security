package com.example.security.global.security.application;

import com.example.security.domain.member.dao.MemberRepository;
import com.example.security.domain.member.entity.Member;
import com.example.security.global.security.dto.CustomUserDetailsDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("유저를 찾을 수 없습니다."));
        // db에서 가져온값 검증 진행
        return CustomUserDetailsDTO.builder()
                .username(member.getUsername())
                .role(member.getRole())
                .password(member.getPassword())
                .build();
    }
}
