package com.example.security.global.config;

import com.example.security.global.security.filter.JwtUtil;
import com.example.security.global.security.filter.JwtFilter;
import com.example.security.global.security.filter.LoginFilter;
import com.example.security.global.security.handler.LoginFailureHandler;
import com.example.security.global.security.handler.LoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(
                        configure -> configure.loginProcessingUrl("/api/login")
                                .successHandler(new LoginSuccessHandler(jwtUtil))
                                .failureHandler(new LoginFailureHandler())
                )
            .httpBasic(AbstractHttpConfigurer::disable)
            // 경로별 인가작업
            .authorizeHttpRequests((auth)-> auth
                .requestMatchers("/login", "/","/register").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated())
            // jwtfilter 등록 - UsernamePasswordAuthenticationFilter 전
            .addFilterBefore(new JwtFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
//            // login filter 등록 - UsernamePasswordAuthenticationFilter 위치에 필터 추가
//            .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class)
            // 세션 설정 - stateless
            .sessionManagement((session)-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }
}
