package dev.roy.springjwt.controller;

import dev.roy.springjwt.config.jwt.JwtService;
import dev.roy.springjwt.config.jwt.LoginForm;
import dev.roy.springjwt.service.JwtUserDetailService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginAuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtUserDetailService jwtUserDetailService;

    public LoginAuthController(AuthenticationManager authenticationManager, JwtService jwtService, JwtUserDetailService jwtUserDetailService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.jwtUserDetailService = jwtUserDetailService;
    }

    @GetMapping("/home")
    public String home() {
        return "Welcome to Spring JWT";
    }

    @GetMapping("/admin/home")
    public String adminHome() {
        return "Welcome to Spring JWT Admin";
    }

    @GetMapping("/user/home")
    public String userHome() {
        return "Welcome to Spring JWT User";
    }

    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody LoginForm loginForm) {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginForm.username(), loginForm.password()
        ));
        if (authenticate.isAuthenticated()) {
            return jwtService.generateToken(jwtUserDetailService.loadUserByUsername(loginForm.username()));
        } else {
            throw new BadCredentialsException("Bad credentials");
        }
    }
}
