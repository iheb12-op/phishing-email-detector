package com.socanalyzer.phishingdetector.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Simple per-IP token-bucket rate limiter for the analysis endpoints
 * (requirement #17). Analysis is CPU/parsing-intensive and accepts
 * untrusted file uploads, so it is a natural target for abuse/DoS —
 * this filter caps each client to a sane request rate.
 *
 * NOTE: in-memory buckets are fine for a single-instance educational
 * deployment. A multi-instance production deployment should back this
 * with Redis (see optional Redis dependency in the project brief).
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getRequestURI().startsWith("/api/analyze")) {
            String clientKey = clientKey(request);
            Bucket bucket = buckets.computeIfAbsent(clientKey, k -> newBucket());
            if (!bucket.tryConsume(1)) {
                response.setStatus(429);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"Rate limit exceeded. Please slow down.\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private Bucket newBucket() {
        // 20 analysis requests per minute per client — generous for interactive use,
        // tight enough to blunt automated abuse.
        Bandwidth limit = Bandwidth.classic(20, io.github.bucket4j.Refill.greedy(20, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private String clientKey(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded.split(",")[0].trim() : request.getRemoteAddr();
    }
}
