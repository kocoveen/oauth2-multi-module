package com.example.resourceserver;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/resource/{id}")
    public ResponseEntity<?> getResource(
        @AuthenticationPrincipal User user,
        @PathVariable int id
    ) {
        return ResponseEntity.ok(user);
    }
}
