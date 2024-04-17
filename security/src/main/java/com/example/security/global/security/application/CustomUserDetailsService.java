package com.example.security.global.security.application;

import com.example.security.domain.member.dao.MemberRepository;
import com.example.security.global.security.dto.CustomUserDetailsDTO;
import com.example.security.domain.member.entity.Member;
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
        Member member = memberRepository.findByUsername(username);
        // db에서 가져온값 검증 진행
        return new CustomUserDetailsDTO(member);
    }
}
