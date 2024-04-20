package com.example.security.domain.member.dao;

import com.example.security.domain.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    // username을 받아 db 테이블에서 회원 조회
    Optional<Member> findByUsername(String username);
}
