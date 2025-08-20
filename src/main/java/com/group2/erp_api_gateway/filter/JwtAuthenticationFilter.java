package com.group2.erp_api_gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * ✅ Global JWT Authentication Filter for API Gateway
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${jwt.secret}")
    private String secret;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        String method = exchange.getRequest().getMethod() != null
                ? exchange.getRequest().getMethod().name()
                : "UNKNOWN";
        String ip = exchange.getRequest().getRemoteAddress() != null
                ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                : "unknown";

        // 🔹 Log mọi request đi qua Gateway
        log.info("🌐 Incoming request: {} {} from IP: {}", method, path, ip);

        // 🚫 Skip JWT check cho public endpoints (ví dụ: /auth/**)
        if (path.startsWith("/auth")) {
            log.info("➡️ Skipping JWT validation for public path: {}", path);
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("❌ Missing or invalid Authorization header on path: {}", path);
            return unauthorizedResponse(exchange, "Missing or invalid Authorization header");
        }

        try {
            String token = authHeader.substring(7);

            // ✅ Parse & validate JWT
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secret.getBytes())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            log.info("✅ JWT validated for path {} - subject: {}", path, claims.getSubject());

            // Lưu claims để service phía sau có thể lấy ra
            exchange.getAttributes().put("claims", claims);

        } catch (Exception e) {
            log.error("❌ JWT validation failed for path {} - reason: {}", path, e.getMessage());
            return unauthorizedResponse(exchange, "Invalid or expired JWT token");
        }

        return chain.filter(exchange);
    }

    /**
     * 🔹 Custom JSON response cho lỗi 401 Unauthorized
     */
    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = String.format(
                "{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"%s\"}",
                message.replace("\"", "'") // tránh lỗi JSON khi message có dấu "
        );

        DataBuffer buffer = exchange.getResponse().bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));

        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -1; // chạy trước các filter khác
    }
}
