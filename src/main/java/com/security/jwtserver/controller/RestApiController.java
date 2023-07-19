package com.security.jwtserver.controller;

import com.security.jwtserver.config.auth.PrincipalDetails;
import com.security.jwtserver.model.User;
import com.security.jwtserver.repository.UserRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
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

	// Tip : JWT를 사용하면 UserDetailsService를 호출하지 않기 때문에 @AuthenticationPrincipal 사용
	// 불가능.
	// 왜냐하면 @AuthenticationPrincipal은 UserDetailsService에서 리턴될 때 만들어지기 때문이다.

	// 유저 혹은 매니저 혹은 어드민이 접근 가능
	@GetMapping("user")
	public String user(Authentication authentication) {
		PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("principal : " + principal.getUser().getId());
		System.out.println("principal : " + principal.getUser().getUsername());
		System.out.println("principal : " + principal.getUser().getPassword());
		System.out.println("principal = " + principal.getUser().getRoleList());

		return "<h1>user</h1>";
	}

	// 매니저 혹은 어드민이 접근 가능
	@GetMapping("manager/reports")
	public String reports() {
		return "<h1>reports</h1>";
	}

	// 어드민이 접근 가능
	@GetMapping("admin/user")
	public List<User> user() {
		return userRepository.findAll();
	}

	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입완료";
	}

}
