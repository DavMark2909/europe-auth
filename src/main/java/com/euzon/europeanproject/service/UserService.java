package com.euzon.europeanproject.service;

import com.euzon.europeanproject.dto.CreateUserDto;
import com.euzon.europeanproject.entity.RoleEntity;
import com.euzon.europeanproject.entity.UserEntity;
import com.euzon.europeanproject.exception.UserExistsException;
import com.euzon.europeanproject.repository.RoleRepository;
import com.euzon.europeanproject.repository.UserRepository;
import com.euzon.europeanproject.security.Converter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username).
                orElseThrow();
        return Converter.convert(user);
    }

    public void createUser(CreateUserDto dto) {
        if (userRepository.existsByUsername(dto.username()))
            throw new UserExistsException();
        UserEntity user = new UserEntity();
        user.setName(dto.name());
        user.setEmail(dto.email());
        user.setPassword(passwordEncoder.encode(dto.password()));
        user.setSurname(dto.surname());
        user.setUsername(dto.username());
        Set<RoleEntity> roles = new HashSet<>();
        for (String role : dto.roles()) {
            RoleEntity roles1 = roleRepository.findByName(role).orElseGet(() -> {
                RoleEntity rolesEntity = new RoleEntity();
                rolesEntity.setName(role);
                return roleRepository.save(rolesEntity);
            });
            roles.add(roles1);
        }
        user.setRoles(roles);
        userRepository.save(user);
    }
}
