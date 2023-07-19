package com.security.jwtserver.config.auth;

import com.security.jwtserver.model.User;
import com.security.jwtserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//http://localhost:8080/login 할때 실행 -> 지금여기서 동작을 못함
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService 의 loadUserByUsername 실행");

		User userEntity = userRepository.findByUsername(username);
		return new PrincipalDetails(userEntity);
	}
}
