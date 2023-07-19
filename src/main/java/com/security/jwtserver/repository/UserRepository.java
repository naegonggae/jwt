package com.security.jwtserver.repository;

import com.security.jwtserver.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

	public User findByUsername(String username);

}
