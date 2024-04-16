package com.example.security.domain.member.entity;

import com.example.security.global.security.converter.PasswordConverter;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(unique = true) // 중복체크
    private String username;
    @Convert(converter = PasswordConverter.class)   // 암호화된 비밀번호 저장
    private String password;
    @Enumerated(EnumType.STRING)
    private Privilege role; // list로 변경
}
