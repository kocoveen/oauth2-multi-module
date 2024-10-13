package com.example.authorizationserver.user;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String password;
    private String nickname;

    @Enumerated(EnumType.STRING)
    private Type type;

    @Enumerated(EnumType.STRING)
    private Role role;

    // Enum classes
    public enum Type {
        OPERATOR
    }

    public enum Role {
        RESOURCE_READ,
        RESOURCE_WRITE
    }

    @Builder
    public User(Long id, String email, String password, String nickname, Type type, Role role) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.type = type;
        this.role = role;
    }
}
