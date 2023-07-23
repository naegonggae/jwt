package com.security.jwtserver.dto;

import lombok.Data;

@Data
public class LoginRequestDto {
	private String username;
	private String password;
}