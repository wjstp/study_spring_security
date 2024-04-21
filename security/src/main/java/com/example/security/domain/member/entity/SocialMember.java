package com.example.security.domain.member.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Getter
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class SocialMember {
    @Id
    @Column(name = "social_member_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

//    private SocialType socialType;

    private String email;

    @ManyToOne
    @JoinColumn(name = "member_id")
    private Member member;


}
