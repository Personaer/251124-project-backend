package store.kanggyoenggu.authservice.auth;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import store.kanggyoenggu.authservice.google.GoogleOAuthService;
import store.kanggyoenggu.authservice.google.GoogleTokenResponse;
import store.kanggyoenggu.authservice.google.GoogleUserInfo;
import store.kanggyoenggu.authservice.jwt.JwtService;
import store.kanggyoenggu.authservice.kakao.KakaoOAuthService;
import store.kanggyoenggu.authservice.kakao.KakaoTokenResponse;
import store.kanggyoenggu.authservice.kakao.KakaoUserInfo;
import store.kanggyoenggu.authservice.naver.NaverOAuthService;
import store.kanggyoenggu.authservice.naver.NaverTokenResponse;
import store.kanggyoenggu.authservice.naver.NaverUserInfo;

// OAuth2 콜백 컨트롤러
// 카카오, 네이버, 구글 OAuth2 콜백 처리
@RestController
@RequestMapping("/oauth2")
public class OAuth2CallbackController {

    private final KakaoOAuthService kakaoOAuthService;
    private final NaverOAuthService naverOAuthService;
    private final GoogleOAuthService googleOAuthService;
    private final JwtService jwtService;

    @Value("${frontend.callback-url}")
    private String frontendCallbackUrl;

    public OAuth2CallbackController(
            KakaoOAuthService kakaoOAuthService,
            NaverOAuthService naverOAuthService,
            GoogleOAuthService googleOAuthService,
            JwtService jwtService) {
        this.kakaoOAuthService = kakaoOAuthService;
        this.naverOAuthService = naverOAuthService;
        this.googleOAuthService = googleOAuthService;
        this.jwtService = jwtService;
    }

    // 카카오 OAuth2 콜백 처리
    @GetMapping("/kakao/callback")
    public ResponseEntity<Void> kakaoCallback(@RequestParam(required = false) String code) {
        if (code != null) {
            return processKakaoCallback(code);
        }

        // code가 없는 경우 에러
        String errorUrl = String.format(
                "%s?error=%s",
                frontendCallbackUrl,
                URLEncoder.encode("missing_code", StandardCharsets.UTF_8));
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(errorUrl));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    // 네이버 OAuth2 콜백 처리
    @GetMapping("/naver/callback")
    public ResponseEntity<Void> naverCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description) {

        // 네이버에서 에러를 반환한 경우
        if (error != null) {
            System.err.println("ERROR: 네이버에서 에러 반환: " + error + " - " + error_description);
            String errorUrl = String.format(
                    "%s?error=%s&error_description=%s",
                    frontendCallbackUrl,
                    URLEncoder.encode(error, StandardCharsets.UTF_8),
                    URLEncoder.encode(error_description != null ? error_description : "", StandardCharsets.UTF_8));
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(errorUrl));
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }

        if (code != null) {
            return processNaverCallback(code);
        }

        // code가 없는 경우 에러
        System.err.println("ERROR: 네이버 콜백에 code가 없습니다.");
        String errorUrl = String.format(
                "%s?error=%s",
                frontendCallbackUrl,
                URLEncoder.encode("missing_code", StandardCharsets.UTF_8));
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(errorUrl));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    // 구글 OAuth2 콜백 처리
    @GetMapping("/google/callback")
    public ResponseEntity<Void> googleCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error) {

        // 구글에서 에러를 반환한 경우
        if (error != null) {
            System.err.println("ERROR: 구글에서 에러 반환: " + error);
            String errorUrl = String.format(
                    "%s?error=%s",
                    frontendCallbackUrl,
                    URLEncoder.encode(error, StandardCharsets.UTF_8));
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(errorUrl));
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }

        if (code != null) {
            return processGoogleCallback(code);
        }

        // code가 없는 경우 에러
        System.err.println("ERROR: 구글 콜백에 code가 없습니다.");
        String errorUrl = String.format(
                "%s?error=%s",
                frontendCallbackUrl,
                URLEncoder.encode("missing_code", StandardCharsets.UTF_8));
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(errorUrl));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    // 카카오 콜백 처리 메서드
    private ResponseEntity<Void> processKakaoCallback(String code) {
        try {
            // frontendCallbackUrl 유효성 검사
            if (frontendCallbackUrl == null || frontendCallbackUrl.trim().isEmpty()) {
                System.err.println("ERROR: frontend.callback-url이 설정되지 않았습니다.");
                return createErrorResponse("FRONTEND_CALLBACK_URL_NOT_CONFIGURED");
            }

            // 1. 액세스 토큰 요청
            KakaoTokenResponse tokenResponse = kakaoOAuthService.getAccessToken(code);
            String accessToken = tokenResponse.getAccessToken();

            // 카카오 액세스 토큰 출력
            System.out.println("Access Token: " + accessToken);

            // 2. 사용자 정보 조회
            KakaoUserInfo userInfo = kakaoOAuthService.getUserInfo(accessToken);

            // 3. 카카오 사용자 정보 추출
            Long kakaoId = userInfo.getId();
            KakaoUserInfo.KakaoAccount kakaoAccount = userInfo.getKakaoAccount();
            KakaoUserInfo.Profile profile = kakaoAccount != null ? kakaoAccount.getProfile() : null;

            String nickname = profile != null ? profile.getNickname() : "사용자";
            String profileImageUrl = profile != null
                    ? (profile.getProfileImageUrl() != null ? profile.getProfileImageUrl() : "없음")
                    : "없음";
            String thumbnailImageUrl = profile != null
                    ? (profile.getThumbnailImageUrl() != null ? profile.getThumbnailImageUrl() : "없음")
                    : "없음";

            // 4. JWT 토큰 생성
            String jwtToken = jwtService.generateToken(kakaoId, nickname);

            // 생성된 JWT 토큰 출력
            System.out.println("JWT Token: " + jwtToken);

            // 5. 프론트엔드로 리다이렉트 (토큰 포함)
            return createRedirectResponse(frontendCallbackUrl, jwtToken, null);

        } catch (Exception e) {
            // 에러 로깅
            System.err.println("ERROR: 콜백 처리 중 예외 발생: " + e.getMessage());
            e.printStackTrace();

            // 에러 발생 시 프론트엔드로 리다이렉트
            return createRedirectResponse(frontendCallbackUrl, null, "login_failed");
        }
    }

    // 네이버 콜백 처리 메서드
    private ResponseEntity<Void> processNaverCallback(String code) {
        try {
            // frontendCallbackUrl 유효성 검사
            if (frontendCallbackUrl == null || frontendCallbackUrl.trim().isEmpty()) {
                System.err.println("ERROR: frontend.callback-url이 설정되지 않았습니다.");
                return createErrorResponse("FRONTEND_CALLBACK_URL_NOT_CONFIGURED");
            }

            // 1. 액세스 토큰 요청
            NaverTokenResponse tokenResponse = naverOAuthService.getAccessToken(code);
            String accessToken = tokenResponse.getAccessToken();

            // 네이버 액세스 토큰 출력
            System.out.println("Access Token: " + accessToken);

            // 2. 사용자 정보 조회
            NaverUserInfo userInfo = naverOAuthService.getUserInfo(accessToken);

            // 3. 네이버 사용자 정보 추출
            NaverUserInfo.Response response = userInfo.getResponse();
            String naverId = response.getId();
            String nickname = response.getNickname() != null ? response.getNickname() : "사용자";
            String name = response.getName() != null ? response.getName() : nickname;
            String profileImageUrl = response.getProfile_image() != null ? response.getProfile_image() : "없음";

            // 4. JWT 토큰 생성
            Long userId;
            try {
                userId = Long.parseLong(naverId);
            } catch (NumberFormatException e) {
                // 네이버 ID가 숫자가 아닌 경우 해시값 사용
                userId = (long) naverId.hashCode();
            }
            String jwtToken = jwtService.generateToken(userId, nickname);

            // 생성된 JWT 토큰 출력
            System.out.println("JWT Token: " + jwtToken);

            // 5. 프론트엔드로 리다이렉트 (토큰 포함)
            return createRedirectResponse(frontendCallbackUrl, jwtToken, null);

        } catch (Exception e) {
            // 에러 로깅
            System.err.println("ERROR: 네이버 콜백 처리 중 예외 발생: " + e.getMessage());
            e.printStackTrace();

            // 에러 발생 시 프론트엔드로 리다이렉트
            return createRedirectResponse(frontendCallbackUrl, null, "login_failed");
        }
    }

    // 구글 콜백 처리 메서드
    private ResponseEntity<Void> processGoogleCallback(String code) {
        try {
            // frontendCallbackUrl 유효성 검사
            if (frontendCallbackUrl == null || frontendCallbackUrl.trim().isEmpty()) {
                System.err.println("ERROR: frontend.callback-url이 설정되지 않았습니다.");
                return createErrorResponse("FRONTEND_CALLBACK_URL_NOT_CONFIGURED");
            }

            // 1. 액세스 토큰 요청
            GoogleTokenResponse tokenResponse = googleOAuthService.getAccessToken(code);
            String accessToken = tokenResponse.getAccessToken();

            // 구글 액세스 토큰 출력
            System.out.println("Access Token: " + accessToken);

            // 2. 사용자 정보 조회
            GoogleUserInfo userInfo = googleOAuthService.getUserInfo(accessToken);

            // 3. 구글 사용자 정보 추출
            String googleId = userInfo.getId();
            String name = userInfo.getName() != null ? userInfo.getName() : "사용자";
            String nickname = name; // 구글은 별명이 없으므로 이름을 별명으로 사용
            String profileImageUrl = userInfo.getPicture() != null ? userInfo.getPicture() : "없음";

            // 4. JWT 토큰 생성
            Long userId;
            try {
                userId = Long.parseLong(googleId);
            } catch (NumberFormatException e) {
                // 구글 ID가 숫자가 아닌 경우 해시값 사용
                userId = (long) googleId.hashCode();
            }
            String jwtToken = jwtService.generateToken(userId, nickname);

            // 생성된 JWT 토큰 출력
            System.out.println("JWT Token: " + jwtToken);

            // 5. 프론트엔드로 리다이렉트 (토큰 포함)
            return createRedirectResponse(frontendCallbackUrl, jwtToken, null);

        } catch (Exception e) {
            // 에러 로깅
            System.err.println("ERROR: 구글 콜백 처리 중 예외 발생: " + e.getMessage());
            e.printStackTrace();

            // 에러 발생 시 프론트엔드로 리다이렉트
            return createRedirectResponse(frontendCallbackUrl, null, "login_failed");
        }
    }

    // 안전한 리다이렉트 응답 생성
    private ResponseEntity<Void> createRedirectResponse(String baseUrl, String token, String error) {
        try {
            // baseUrl 유효성 검사
            if (baseUrl == null || baseUrl.trim().isEmpty()) {
                System.err.println("ERROR: 리다이렉트 URL이 설정되지 않았습니다.");
                baseUrl = "http://localhost:3000/dashboard"; // 기본값
            }

            // URL 생성
            String redirectUrl;
            if (token != null) {
                // 성공: 토큰 포함
                String encodedToken = URLEncoder.encode(token, StandardCharsets.UTF_8);
                redirectUrl = String.format("%s?token=%s", baseUrl, encodedToken);
            } else if (error != null) {
                // 실패: 에러 포함
                redirectUrl = String.format("%s?error=%s", baseUrl, URLEncoder.encode(error, StandardCharsets.UTF_8));
            } else {
                // 기본 리다이렉트
                redirectUrl = baseUrl;
            }

            // URI 생성 및 검증
            URI redirectUri;
            try {
                redirectUri = URI.create(redirectUrl);
            } catch (IllegalArgumentException e) {
                System.err.println("ERROR: 잘못된 리다이렉트 URL 형식: " + redirectUrl);
                System.err.println("ERROR: " + e.getMessage());
                // 기본 URL로 폴백
                redirectUri = URI.create("http://localhost:3000/dashboard?error=redirect_url_invalid");
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(redirectUri);

            return new ResponseEntity<>(headers, HttpStatus.FOUND);

        } catch (Exception e) {
            // 리다이렉트 생성 실패 시 기본 에러 응답
            System.err.println("ERROR: 리다이렉트 응답 생성 실패: " + e.getMessage());
            e.printStackTrace();

            HttpHeaders headers = new HttpHeaders();
            try {
                headers.setLocation(URI.create("http://localhost:3000/dashboard?error=redirect_failed"));
            } catch (Exception ex) {
                System.err.println("ERROR: 기본 리다이렉트 URL도 실패: " + ex.getMessage());
            }

            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // 에러 응답 생성
    private ResponseEntity<Void> createErrorResponse(String errorMessage) {
        return createRedirectResponse(frontendCallbackUrl, null, errorMessage);
    }
}
