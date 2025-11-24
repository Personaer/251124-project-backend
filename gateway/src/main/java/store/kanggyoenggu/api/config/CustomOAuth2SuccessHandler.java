package store.kanggyoenggu.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import store.kanggyoenggu.api.service.JwtService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class CustomOAuth2SuccessHandler implements ServerAuthenticationSuccessHandler {

    private final JwtService jwtService;

    @Value("${frontend.login-callback-url:http://localhost:3000/dashboard}")
    private String frontendCallbackUrl;

    public CustomOAuth2SuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        ServerWebExchange exchange = webFilterExchange.getExchange();
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        try {
            Map<String, Object> attributes = oauth2User.getAttributes();
            @SuppressWarnings("unchecked")
            Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
            @SuppressWarnings("unchecked")
            Map<String, Object> profile = (Map<String, Object>) (kakaoAccount != null ? kakaoAccount.get("profile")
                    : null);

            Long kakaoId = ((Number) attributes.get("id")).longValue();
            String nickname = profile != null ? (String) profile.get("nickname") : "";

            // JWT 토큰 발급
            String token = jwtService.generateToken(kakaoId, nickname);

            // 프론트엔드로 리다이렉트 (토큰을 쿼리 파라미터로 전달)
            String callbackUrl = (frontendCallbackUrl != null && !frontendCallbackUrl.isEmpty())
                    ? frontendCallbackUrl
                    : "http://localhost:3000/dashboard";
            String redirectUrl = callbackUrl + "?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);

            org.springframework.http.server.reactive.ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(org.springframework.http.HttpStatus.FOUND);
            response.getHeaders().setLocation(java.net.URI.create(redirectUrl));

            return response.setComplete();
        } catch (Exception e) {
            // 에러 발생 시 실패 페이지로 리다이렉트
            String callbackUrl = (frontendCallbackUrl != null && !frontendCallbackUrl.isEmpty())
                    ? frontendCallbackUrl
                    : "http://localhost:3000/dashboard";
            String errorUrl = callbackUrl + "?error=login_failed";
            org.springframework.http.server.reactive.ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(org.springframework.http.HttpStatus.FOUND);
            response.getHeaders().setLocation(java.net.URI.create(errorUrl));

            return response.setComplete();
        }
    }
}
