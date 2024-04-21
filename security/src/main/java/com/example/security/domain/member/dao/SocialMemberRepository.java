package com.example.security.domain.member.dao;

import com.example.security.domain.member.entity.SocialMember;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface SocialMemberRepository extends JpaRepository<SocialMember, UUID> {
}
