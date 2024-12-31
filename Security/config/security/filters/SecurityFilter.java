package com.gramseva.config.security.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gramseva.exception.UnauthorizedException;
import com.gramseva.payload.responses.ErrorResponse;
import com.gramseva.utils.AppUtils;
import com.gramseva.utils.Constants;
import com.gramseva.utils.JwtUtils;
import com.gramseva.utils.TokenType;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AppUtils appUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String tokenHeader = request.getHeader("Authorization");
        if (tokenHeader != null) {
            try {
                String token = this.appUtils.getTokenFromHeader(tokenHeader);
                System.out.println(token);
                if (!this.isPublic(request.getRequestURI())) {
                    if (!this.isValid(token)) {
                        this.handleException(response, Constants.INVALID_TOKEN);
                        return;
                    }
                }
                String userId = this.jwtUtils.extractUsername(token);
                System.out.println(userId);
                UserDetails user = this.userDetailsService.loadUserByUsername(userId);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userId, user.getPassword(), user.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            } catch (ExpiredJwtException | MalformedJwtException | SignatureException ex) {
                // Handle expired token
ex.printStackTrace();
                handleException(response, Constants.INVALID_TOKEN);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean isPublic(String uri) {
        return uri.contains("public");
    }

    public boolean isValid(String token) {
        TokenType type = TokenType.valueOf((String) this.jwtUtils.getTokenType(token));
        return type.equals(TokenType.ACCESS);
    }

    public void handleException(HttpServletResponse response, String message) {
        ErrorResponse error = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED, message);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        String errorMessage = "";
        ObjectMapper mapper = new ObjectMapper();
        try {
            errorMessage = mapper.writeValueAsString(error);
        } catch (JsonProcessingException ex) {
            ex.printStackTrace();
        }

        byte[] bytes = errorMessage.getBytes(StandardCharsets.UTF_8);
        try {
            response.getOutputStream().write(bytes);
            response.getOutputStream().close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
