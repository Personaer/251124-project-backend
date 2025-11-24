package store.kanggyoenggu.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class CustomOAuth2FailureHandler implements ServerAuthenticationFailureHandler {

    @Value("${frontend.login-callback-url:http://localhost:3000/dashboard}")
    private String frontendCallbackUrl;

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange,
            org.springframework.security.core.AuthenticationException exception) {
        ServerWebExchange exchange = webFilterExchange.getExchange();

        String errorMessage = exception.getMessage();
        String callbackUrl = (frontendCallbackUrl != null && !frontendCallbackUrl.isEmpty())
                ? frontendCallbackUrl
                : "http://localhost:3000/dashboard";
        String errorUrl = callbackUrl + "?error=" + URLEncoder
                .encode(errorMessage != null ? errorMessage : "authentication_failed", StandardCharsets.UTF_8);

        org.springframework.http.server.reactive.ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(org.springframework.http.HttpStatus.FOUND);
        response.getHeaders().setLocation(java.net.URI.create(errorUrl));

        return response.setComplete();
    }
}
