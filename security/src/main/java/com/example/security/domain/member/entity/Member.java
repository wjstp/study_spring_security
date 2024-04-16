package com.example.security.domain.member.entity;

import com.example.security.global.security.converter.PasswordConverter;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    @Convert(converter = PasswordConverter.class)   // 암호화된 비밀번호 저장
    private String password;
    @Enumerated(EnumType.STRING)
    private Privilege role; // list로 변경
}
