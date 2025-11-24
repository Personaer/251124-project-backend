package store.kanggyoenggu.api.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import store.kanggyoenggu.api.service.JwtService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthController {

    private final JwtService jwtService;

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * 현재 사용자 정보 조회
     * Authorization 헤더에서 JWT 토큰을 받아 사용자 정보를 반환
     */
    @GetMapping("/me")
    public Mono<ResponseEntity<Map<String, Object>>> getCurrentUser(
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        return Mono.fromCallable(() -> {
            Map<String, Object> response = new HashMap<>();

            // Authorization 헤더 확인
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                response.put("success", false);
                response.put("message", "토큰이 없습니다.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            // Bearer 제거
            String token = authorization.substring(7);

            try {
                // JWT 토큰 파싱
                Map<String, Object> claims = jwtService.parseToken(token);

                // 사용자 정보 구성
                Map<String, Object> user = new HashMap<>();
                user.put("id", claims.get("sub")); // subject는 kakaoId
                user.put("kakaoId", claims.get("kakaoId"));
                user.put("nickname", claims.get("nickname"));

                response.put("success", true);
                response.put("message", "사용자 정보 조회 성공");
                response.put("user", user);

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                response.put("success", false);
                response.put("message", "토큰이 유효하지 않습니다: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
        });
    }

    /**
     * 로그아웃 처리
     * JWT 토큰 기반이므로 클라이언트에서 토큰을 제거하면 됨
     * 서버 측에서는 성공 응답만 반환
     */
    @PostMapping("/logout")
    public Mono<ResponseEntity<Map<String, Object>>> logout() {
        return Mono.fromCallable(() -> {
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "로그아웃 성공");
            return ResponseEntity.ok(response);
        });
    }
}
