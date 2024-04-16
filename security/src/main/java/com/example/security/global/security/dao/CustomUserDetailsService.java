package com.example.security.global.security.dao;

import com.example.security.domain.member.repository.MemberRepository;
import com.example.security.global.security.dto.CustomUserDetails;
import com.example.security.domain.member.entity.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member memberData = memberRepository.findByUsername(username);
        // db에서 가져온값 검증 진행
        if (Objects.nonNull(memberData)) {
            return new CustomUserDetails(memberData);
        }
        return null;
    }
}
