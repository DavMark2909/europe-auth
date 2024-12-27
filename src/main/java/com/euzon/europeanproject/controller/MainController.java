package com.euzon.europeanproject.controller;

import com.euzon.europeanproject.dto.CreateUserDto;
import com.euzon.europeanproject.repository.UserRepository;
import com.euzon.europeanproject.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class MainController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity create(@RequestBody CreateUserDto dto){
        try{
            userService.createUser(dto);
            return ResponseEntity.ok().build();
        } catch (RuntimeException e){
            return ResponseEntity.badRequest().build();
        }
    }
}
