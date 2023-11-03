package com.example.demo.service;

import com.example.demo.domain.user.Authority;
import com.example.demo.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserAuthorityRepository extends JpaRepository<Authority, Long> {
}
