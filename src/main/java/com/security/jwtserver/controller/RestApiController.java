package com.security.jwtserver.controller;

import com.security.jwtserver.model.User;
import com.security.jwtserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
//@CrossOrigin // 이거는 인증이 필요하지않은 요청만 허용됨 그래서 SecurityConfig 에서 cors 필터를 적용시킨다.
@RestController
@RequiredArgsConstructor
public class RestApiController {

	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final UserRepository userRepository;

	@GetMapping("/home")
	public String home() {
		return "<h1>home</h1>";
	}

	@PostMapping("/token")
	public String token() {
		return "<h1>token</h1>";
	}

	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입완료";
	}

}
