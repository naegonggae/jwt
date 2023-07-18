package com.security.jwtserver.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
//@CrossOrigin // 이거는 인증이 필요하지않은 요청만 허용됨 그래서 SecurityConfig 에서 cors 필터를 적용시킨다.
@RestController
public class RestApiController {

	@GetMapping("/home")
	public String home() {
		return "<h1>home</h1>";
	}

}
