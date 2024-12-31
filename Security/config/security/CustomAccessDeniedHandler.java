package com.gramseva.config.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gramseva.payload.responses.ErrorResponse;
import com.gramseva.utils.Constants;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ErrorResponse error = new ErrorResponse(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN, Constants.ACCESS_DENIED);
        response.setStatus(HttpStatus.FORBIDDEN.value());
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
