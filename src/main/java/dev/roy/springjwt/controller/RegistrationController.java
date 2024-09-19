package dev.roy.springjwt.controller;

import dev.roy.springjwt.model.JwtUser;
import dev.roy.springjwt.repository.JwtUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RegistrationController {

    private final PasswordEncoder passwordEncoder;
    private final JwtUserRepository jwtUserRepository;

    public RegistrationController(PasswordEncoder passwordEncoder, JwtUserRepository jwtUserRepository) {
        this.passwordEncoder = passwordEncoder;
        this.jwtUserRepository = jwtUserRepository;
    }

    @PostMapping("/register/user")
    public JwtUser register(@RequestBody JwtUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return jwtUserRepository.save(user);
    }
}
