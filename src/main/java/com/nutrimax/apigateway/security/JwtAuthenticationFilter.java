package com.nutrimax.apigateway.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    // Rutas que NO requieren token (publicas)
    private final List<String> rutasPublicas = List.of(
            "/api/auth/login",
            "/api/auth/registro");

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Si la ruta es publica, dejar pasar sin validar
        if (esRutaPublica(path)) {
            return chain.filter(exchange);
        }

        // Verificar que venga el header Authorization
        // Verificar que venga el header Authorization
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return rechazar(exchange,
                    "Falta el header Authorization o el formato es invalido, debe ser 'Bearer <token>'");
        }

        String token = authHeader.substring(7); // quitar "Bearer "

        if (!jwtUtil.isTokenValid(token)) {
            return rechazar(exchange, "Token invalido o expirado");
        }

        // Token valido: agregar info del usuario como headers para el microservicio
        // destino
        String email = jwtUtil.getEmailFromToken(token);
        String rol = jwtUtil.getRolFromToken(token);

        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-User-Email", email)
                .header("X-User-Rol", rol)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private boolean esRutaPublica(String path) {
        return rutasPublicas.stream().anyMatch(path::equals);
    }

    private Mono<Void> rechazar(ServerWebExchange exchange, String mensaje) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add("Content-Type", "application/json");

        String body = "{\"error\": \"" + mensaje + "\"}";
        byte[] bytes = body.getBytes();

        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }

    @Override
    public int getOrder() {
        return -1; // se ejecuta antes que otros filtros
    }
}