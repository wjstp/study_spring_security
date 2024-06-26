package com.example.security.global.security.dto;

import com.example.security.domain.member.entity.Privilege;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@Getter
@Builder
public class OAuth2LoginDTO implements OAuth2User {

    private String username;

    private Privilege role;

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of("email", this.username);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getName() {
        return this.username;
    }
}
