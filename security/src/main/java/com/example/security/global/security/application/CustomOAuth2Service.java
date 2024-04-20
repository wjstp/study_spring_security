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

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2Service extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        System.out.println("##############");
        System.out.println(request.getAdditionalParameters());
        System.out.println("여기까진?");
        OAuth2User oAuth2User = super.loadUser(request);
        System.out.println("ghdldldldldldl");
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
        Member member = memberRepository.findByUsername(email).orElseGet(()-> registerMember(oAuth2User));
        return OAuth2LoginDTO.builder()
                .username(member.getUsername())
                .role(Privilege.USER)
                .build();
    }

    public Member registerMember(OAuth2User oAuth2User) {
        Map<String, Object> response = (Map<String, Object>) oAuth2User.getAttributes().get("kakao_account");
        log.info("소셜 로그인 시 회원 가입");
        return memberRepository.save(
                Member.builder()
                        .username(response.get("email").toString())
                        .role(Privilege.USER)
                        .build());
    }



}
