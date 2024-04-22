package com.example.security.global.security.application;

import com.example.security.domain.member.dao.MemberRepository;
import com.example.security.domain.member.entity.Member;
import com.example.security.domain.member.entity.Privilege;
import com.example.security.global.security.dto.OAuth2LoginDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2Service extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(request);
        log.info("user: " + oAuth2User.getAuthorities().toString());

        String clientId = request.getClientRegistration().getRegistrationId();
        String email = switch (clientId) {
            case "kakao" -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> response = (Map<String, Object>) oAuth2User.getAttributes().get("kakao_account");
                System.out.println(oAuth2User.getAttributes());
                yield (String) response.get("email");
            }
            default -> throw new IllegalStateException("Unexcepted value: " + clientId);
        };
        // db에서 조회, 없다면 가입
        Member member = memberRepository.findByUsername(email).orElseGet(() -> registerMember(oAuth2User));
        var result = OAuth2LoginDTO.builder()
                .username(member.getUsername())
                .role(Privilege.USER)
                .build();
        System.out.println(result);
        return result;
    }

    public Member registerMember(OAuth2User oAuth2User) {
        Map<String, Object> response = (Map<String, Object>) oAuth2User.getAttributes().get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) response.get("profile");
        log.info("소셜 로그인 시 회원 가입");
        return memberRepository.save(
                Member.builder()
                        .nickname((String) profile.get("nickname"))
                        .username(response.get("email").toString())
                        .role(Privilege.USER)
                        .password(String.valueOf(UUID.randomUUID()))
                        .build());
    }


}
