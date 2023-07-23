package com.security.jwtserver.config.auth;

import com.security.jwtserver.model.User;
import com.security.jwtserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService - loadUserByUsername 실행");

		User userEntity = userRepository.findByUsername(username);
		System.out.println("PrincipalDetailsService - userEntity = " + userEntity);
		System.out.println("PrincipalDetailsService - loadUserByUsername 종료");

		return new PrincipalDetails(userEntity);
	}
}
