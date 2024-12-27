package com.euzon.europeanproject.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Table(name = "user")
@NoArgsConstructor
@Builder
@Setter
@Getter
@Entity
@AllArgsConstructor
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;
    private String email;
    private String name;
    private String surname;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleEntity> roles;
}
