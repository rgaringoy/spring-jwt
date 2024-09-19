package dev.roy.springjwt.repository;

import dev.roy.springjwt.model.JwtUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JwtUserRepository extends JpaRepository<JwtUser, Long> {

    Optional<JwtUser> findByUsername(String username);
}
