package com.example.security.global.config;

import com.example.security.global.security.application.JwtService;
import com.example.security.global.security.filter.JwtFilter;
import com.example.security.global.security.util.JwtUtil;
import com.example.security.global.security.handler.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final JwtService jwtService;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // csrf를 disable 설정 : stateless 상태로 관리하기 때문에 csrf 공격을 관리하지 않아도 됨
        http.csrf(AbstractHttpConfigurer::disable)
                // 세션 설정 - stateless
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 경로별 인가작업
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/nickname" , "/login","/oauth2/authorization/kakao", "/auth/refresh", "/api/login",  "/", "/register" ).permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(
                        configure -> configure
                                .loginProcessingUrl("/api/login")
                                .successHandler(new LoginSuccessHandler(jwtUtil, jwtService))
                                .failureHandler(new LoginFailureHandler())
                )
                .oauth2Login(
                        oauth2 -> oauth2
                                .successHandler(new CustomOauth2SuccessHandler(jwtUtil, jwtService))
                                .failureHandler(new CustomOauth2FailureHandler())
                )
                .exceptionHandling(
                        configurer -> configurer.accessDeniedHandler(new CustomAccessDeniedHandler())
//                                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                )
                // http basic auth 기반으로 한 로그인 인증창 사용하지않으므로 disable
                .httpBasic(AbstractHttpConfigurer::disable)
                // jwtfilter 등록 - UsernamePasswordAuthenticationFilter 전
                .addFilterBefore(new JwtFilter(jwtService), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of(
                "http://localhost:3000",
                "http://localhost:8080"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(List.of(
                "Authorization",
                "Cache-Control",
                "Content-Type"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
