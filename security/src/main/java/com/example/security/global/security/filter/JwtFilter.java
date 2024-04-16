package com.example.security.global.security.filter;

import com.example.security.domain.member.entity.Privilege;
import com.example.security.global.security.dto.CustomUserDetails;
import com.example.security.domain.member.entity.Member;
import io.jsonwebtoken.Claims;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
//요청에 대해 한번만 작동하는 필터 onceperrequestfilter
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @Nonnull FilterChain filterChain) throws ServletException, IOException {
        // request에서 Authorization헤더를 찾음
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("토큰이 없거나 접두사가 일치하지 않습니다.");
            // 다음 필터로 넘긴다.
            filterChain.doFilter(request, response);
            // 조건이 해당되면 메서드 종료
            return;
        }

        System.out.println("토큰 검증 시작합니다.");
        // Bearer 제거 후 순수 토큰 획득
        String token = authorization.split(" ")[1];

        Claims claims = jwtUtil.verifyJwtToken(token);
        String username = claims.getSubject();
        String role = claims.get("roles").toString();   // 수정
        // member를 생성하여 값 set
        // token에 password 정보가 없고, db에서 조회하는 방식은 비효율적이라 임의값 넣어준다.
        Member member = Member.builder()
                .username(username)
                .password("tmppassword")
                .role(Privilege.valueOf(role))
                .build();

        // userDetails에 회원 정보 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(member);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        // 세션에 사용자 등록 - securitycontextholder에 등록한다.
        SecurityContextHolder.getContext().setAuthentication(authToken);
        // 그 다음 필터로 이동
        filterChain.doFilter(request, response);

    }
}
