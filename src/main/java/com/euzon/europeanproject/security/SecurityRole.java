package com.euzon.europeanproject.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public class SecurityRole implements GrantedAuthority {

    private final String role;

    @Override
    public String getAuthority() {
        return role;
    }
}
