package com.security.jwtserver.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import lombok.Data;

@Entity
@Data
public class User {

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String username;
	private String password;
	private String roles; // USER, ADMIN

	// role 이 두개이상일때 조회 메서드
	// ENUM으로 안하고 ,로 해서 구분해서 ROLE을 입력 -> 그걸 파싱!!
	public List<String> getRoleList() {
		if (this.roles.length() > 0) {
			return Arrays.asList(this.roles.split(","));
		}
		return new ArrayList<>();
	}
}
