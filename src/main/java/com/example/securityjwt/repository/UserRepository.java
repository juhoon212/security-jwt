package com.example.securityjwt.repository;

import com.example.securityjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    Boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
