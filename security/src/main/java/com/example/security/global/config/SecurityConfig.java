package com.example.security.global.config;

import com.example.security.global.security.filter.JwtUtil;
import com.example.security.global.security.filter.JwtFilter;
import com.example.security.global.security.filter.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // security를 위한 config
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // csrf를 disable 설정 : stateless 상태로 관리하기 때문에 csrf 공격을 관리하지 않아도 됨
        http.csrf((auth) -> auth.disable());
        // form 로그인 방식 disable
        http.formLogin((auth)-> auth.disable());
        // http basic 인증 방식 disable
        http.httpBasic((auth)-> auth.disable());
        // 경로별 인가작업
        http.authorizeHttpRequests((auth)-> auth
                .requestMatchers("/login", "/","/register").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
        );
        // jwtfilter 등록
        http.addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class);

        // login filter 등록 - UsernamePasswordAuthenticationFilter 위치에 필터 추가
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정 - stateless
        http.sessionManagement((session)-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }
}
