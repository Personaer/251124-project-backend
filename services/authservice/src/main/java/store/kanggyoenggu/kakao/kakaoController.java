package store.kanggyoenggu.kakao;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth/kakao")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class kakaoController {

    /**
     * 카카오 로그인 요청 처리 (GET)
     * 무조건 성공으로 처리하여 Next.js에서 다음 페이지로 이동할 수 있도록 함
     */
    @GetMapping("/login")
    public ResponseEntity<Map<String, Object>> kakaoLogin() {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "카카오 로그인 성공");
        response.put("status", "success");
        response.put("token", "mock-jwt-token-for-testing");
        response.put("redirect", true);

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * 카카오 로그인 요청 처리 (POST)
     * 무조건 성공으로 처리하여 Next.js에서 다음 페이지로 이동할 수 있도록 함
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> kakaoLoginPost(
            @RequestBody(required = false) Map<String, Object> request) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "카카오 로그인 성공");
        response.put("status", "success");
        response.put("token", "mock-jwt-token-for-testing");
        response.put("redirect", true);

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * 카카오 콜백 처리
     */
    @PostMapping("/callback")
    public ResponseEntity<Map<String, Object>> kakaoCallback(
            @RequestBody(required = false) Map<String, Object> request) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "카카오 콜백 처리 성공");
        response.put("status", "success");
        response.put("token", "mock-jwt-token-for-testing");
        response.put("redirect", true);

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * 사용자 정보 조회
     */
    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getUserInfo() {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "사용자 정보 조회 성공");
        response.put("status", "success");
        response.put("user", Map.of(
                "id", "mock-user-id",
                "nickname", "테스트 사용자",
                "email", "test@example.com"));

        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
