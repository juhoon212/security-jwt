package com.example.securityjwt.service;

import com.example.securityjwt.jwt.JWTUtil;
import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Service;

@Service
public class ReIssueService {

    public final JWTUtil jwtUtil;

    public ReIssueService(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    public String makeNewAccessToken(String refreshToken) {

        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        // make new JWT
        return jwtUtil.createJWT("access", username, role, 600000L);
    }

    public String makeNewRefreshToken(String refreshToken) {

        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        // make new JWT
        return jwtUtil.createJWT("refresh", username, role, 86400000L);
    }

    public Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        cookie.setHttpOnly(true);

        return cookie;
    }
}
