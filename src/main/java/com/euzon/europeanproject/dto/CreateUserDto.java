package com.euzon.europeanproject.dto;

import java.util.List;

public record CreateUserDto(
        String name,
        String surname,
        String password,
        String username,
        String email,
        List<String> roles
) {
}
