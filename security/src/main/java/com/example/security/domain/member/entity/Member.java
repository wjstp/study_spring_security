package com.example.security.domain.member.entity;

import com.example.security.global.security.converter.PasswordConverter;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicUpdate;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@DynamicUpdate
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(unique = true)  // 중복체크
    private String username;
    private Date birth;
    private String nickname;
    @Convert(converter = PasswordConverter.class)   // 암호화된 비밀번호 저장
    private String password;
    @Enumerated(EnumType.STRING)
    private Privilege role; // list로 변경

    public void modifyNickname(String nickname) {
        this.nickname = nickname;
    }
}
