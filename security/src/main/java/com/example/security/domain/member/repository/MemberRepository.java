package com.example.security.domain.member.repository;

import com.example.security.domain.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    boolean existsByUsernameAndPassword(String username, String password);

    // username을 받아 db 테이블에서 회원 조회
    Member findByUsername(String username);
}
