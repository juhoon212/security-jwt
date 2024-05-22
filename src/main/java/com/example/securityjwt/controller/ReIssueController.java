package com.example.securityjwt.controller;

import com.example.securityjwt.jwt.JWTUtil;
import com.example.securityjwt.service.ReIssueService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReIssueController {

    private final JWTUtil jwtUtil;
    private final ReIssueService reIssueService;


    public ReIssueController(JWTUtil jwtUtil, ReIssueService reIssueService) {
        this.jwtUtil = jwtUtil;
        this.reIssueService = reIssueService;
    }

    @PostMapping("/reIssue")
    public ResponseEntity<?> reIssue(HttpServletRequest request, HttpServletResponse response) {

        String refresh = null;
        Cookie[] cookies = request.getCookies();

        for (Cookie cookie :cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        try {
            jwtUtil.isExpired(refresh);
        }catch (ExpiredJwtException e) {
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        String newAccess = reIssueService.makeNewAccessToken(refresh);
        String newRefreshToken = reIssueService.makeNewRefreshToken(refresh);

        response.setHeader("access", newAccess);
        response.addCookie(reIssueService.createCookie("refresh", newRefreshToken));

        return new ResponseEntity<> (HttpStatus.OK);

    }
}
