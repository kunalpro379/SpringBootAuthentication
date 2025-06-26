package com.auth.config;

import com.auth.dto.MessageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.HashMap;
import java.util.Map;

@ExceptionHandler(MethodArgumentNotValidException.class)
public class GlobalExceptionHandler {
     public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
          Map<String, String> errors = new HashMap<>();
          ex.getBindingResult().getAllErrors().forEach((error) -> {
               String fieldName = ((fieldError) error).getField();
               String errorMessage = error.getDefaultMessage();
               errors.put(fieldName, errorMessage);
          });
          return ResponseEntity.badRequest().body(errors);
     }

     @ExceptionHandler(RuntimeException.class)
     public RespnoseEntity<MessageResponse> handleRuntimeException(RuntimeException ex) {
          return ResponseEntity.badRequest().body(new MessageRequest(ex.getMessage()));
     }

     @ExceptionHandler(BadCredentialsException.class)
     public ResponseEntity<MessageRespose> handleBadCredentials() {
     }

     @ExceptionHandler(UsernameNotFoundException.class)
     public ResponseEntity<MessageResponse> handleUserNotFound(UserPrincipalNotFoundException ex) {
          return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new MessageResponse(ex.getMessage()));
     }

     @ExceptionHandler(UserAlreadyExistsException.class)
     public ResponseEntity<MessageResponse> handleUserAlreadyExists(UserAlreadyExistsException ex) {
          return ResponseEntity.status(HttpStatus.CONFLICT).body(new MessageResponse(ex.getMessage()));
     }

     @ExceptionHandler(InvalidTokenException.class)
     public ResponseEntity<MessageResponse> handleInvalidToken(InvalidTokenException ex) {
          return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse(ex.getMessage()));
     }

}