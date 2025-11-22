package com.example.microservices.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Standardized API response wrapper for all successful responses
 * @param <T> Type of data being returned
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    private String code;
    private String message;
    private T data;
    private String errorCode;
    private Instant timestamp;

    /**
     * Creates a success response with data
     * @param data Response data
     * @return ApiResponse with success status
     */
    public static <T> ApiResponse<T> success(T data) {
        return ApiResponse.<T>builder()
                .code("SUCCESS")
                .message("Request processed successfully")
                .data(data)
                .timestamp(Instant.now())
                .build();
    }

    /**
     * Creates a success response with data and custom message
     * @param data Response data
     * @param message Custom success message
     * @return ApiResponse with success status
     */
    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .code("SUCCESS")
                .message(message)
                .data(data)
                .timestamp(Instant.now())
                .build();
    }

    /**
     * Creates an error response
     * @param errorCode Error code
     * @param message Error message
     * @return ApiResponse with error status
     */
    public static <T> ApiResponse<T> error(String errorCode, String message) {
        return ApiResponse.<T>builder()
                .code("ERROR")
                .errorCode(errorCode)
                .message(message)
                .timestamp(Instant.now())
                .build();
    }
}
