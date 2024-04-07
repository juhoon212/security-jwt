package com.example.securityjwt.jwt;

import com.example.securityjwt.dto.CustomUserDetails;
import com.example.securityjwt.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");

        // Authorization 헤더 검증
        if(authorization == null || !authorization.startsWith("Bearer ")) {

            logger.info("token null");
            filterChain.doFilter(request, response);

            // 조건이 해당되면 메소드 종료 (필수)
            return;
        }

        // Bearer 기준으로 자른다.
        String token = authorization.split(" ")[1];

        if(jwtUtil.isExpired(token)) {

            logger.info("token expired");
            filterChain.doFilter(request, response);
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temp");
        userEntity.setRole(role);

        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);


        //Principal(접근 주체) : 보호 받는 리소스에 접근하는 대상
        //Credential(비밀번호) : 리소스에 접근하는 대상의 비밀번호
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                customUserDetails, null, customUserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }

    public static void main(String[] args) {

        int i1 = 5;
        int i2 = 3;


        System.out.println(i1 | i2);
    }
}
