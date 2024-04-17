package com.example.security.global.security.application;

import com.example.security.domain.member.entity.Member;
import com.example.security.domain.member.entity.Privilege;
import com.example.security.global.security.dto.CustomUserDetailsDTO;
import com.example.security.global.security.filter.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtUtil jwtUtil;
    private static final String ACCESS_HEADER_AUTHORIZATION = "Authorization";
    private static final String TOKEN_PREFIX = "BEARER ";

    public Authentication authenticateJwtToken(HttpServletRequest request) {
        String token = parseJwt(request);
        Claims claims = verifyJwtToken(token);
        String username = claims.getSubject();
        String role = claims.get("role").toString();   // 수정
        // member를 생성하여 값 set
        // token에 password 정보가 없고, db에서 조회하는 방식은 비효율적이라 임의값 넣어준다.
        Member member = Member.builder()
                .username(username)
                .password("tmppassword")
                .role(Privilege.valueOf(role))
                .build();

        // userDetails에 회원 정보 담기
        CustomUserDetailsDTO customUserDetails = new CustomUserDetailsDTO(member);

        // 스프링 시큐리티 인증 토큰 생성
        return new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
    }


    public String parseJwt(HttpServletRequest request) {
        // request에서 Authorization헤더를 찾음
        String authorization = request.getHeader(ACCESS_HEADER_AUTHORIZATION);

        // Authorization 헤더 검증
        if (Objects.isNull(authorization)){
            System.out.println("토큰이 존재하지 않습니다.");
            return null;
        }
        if(!authorization.startsWith(TOKEN_PREFIX)) {
            System.out.println("접두사가 일치하지 않습니다.");
            return null;
        }
        // Bearer 제거 후 순수 토큰 획득
        return authorization.split(" ")[1];
    }

    
    public Claims verifyJwtToken(String token) {
        System.out.println("토큰 검증 시작");
        try {
            return jwtUtil.verifyJwtToken(token);
        } catch(MalformedJwtException malformedJwtException) {
            throw new RuntimeException("Malformed Token");
        }
    }
}
