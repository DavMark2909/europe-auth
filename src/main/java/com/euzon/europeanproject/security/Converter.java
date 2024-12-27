package com.euzon.europeanproject.security;

import com.euzon.europeanproject.entity.RoleEntity;
import com.euzon.europeanproject.entity.UserEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public class Converter {

    public static UserDetails convert(UserEntity user) {
        return new SecurityUser(user.getUsername(), user.getPassword(),
                user.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet()));
    }
}
