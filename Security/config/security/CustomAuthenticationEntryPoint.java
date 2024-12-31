package com.gramseva.config.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gramseva.payload.responses.ErrorResponse;
import com.gramseva.utils.Constants;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {


    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        authException.printStackTrace();
        ErrorResponse error = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED, Constants.UNAUTHORIZED_ACCESS);
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
        response.getOutputStream().write(bytes);
    }
}
