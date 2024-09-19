package dev.roy.springjwt.service;

import dev.roy.springjwt.model.JwtUser;
import dev.roy.springjwt.repository.JwtUserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class JwtUserDetailService implements UserDetailsService {

    private final JwtUserRepository jwtUserRepository;

    public JwtUserDetailService(JwtUserRepository jwtUserRepository) {
        this.jwtUserRepository = jwtUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<JwtUser> user = jwtUserRepository.findByUsername(username);
        if(user.isPresent()) {
            var userObj = user.get();
            return User.builder()
                    .username(userObj.getUsername())
                    .password(userObj.getPassword())
                    .roles(getRoles(userObj))
                    .build();
        } else {
            throw new UsernameNotFoundException(username);
        }
    }

    private String[] getRoles(JwtUser user) {
        if (user.getRole() == null) {
            return new String[]{"USER"};
        }
        return user.getRole().split(",");
    }
}
