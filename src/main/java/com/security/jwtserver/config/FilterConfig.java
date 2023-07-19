package com.security.jwtserver.config;

import com.security.jwtserver.filter.MyFilter1;
import com.security.jwtserver.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

//@Configuration
public class FilterConfig {
	// 필터를 직접 만들어버림 시큐리티 필터에 커스텀 필터를 적용시키지 않고 config 하나 파서 필터를 적용가능하다
	// 순서는 시큐리티 필터가 실행되고 그 다음에 실행된다.
	// 필터를 이용해서 jwt 를 구현해보자
	@Bean
	public FilterRegistrationBean<MyFilter1> filter1() {
		FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
		bean.addUrlPatterns("/*");
		bean.setOrder(1); // 낮은 번호가 필터중에서 가장먼저 실행됨
		return bean;
	}

	@Bean
	public FilterRegistrationBean<MyFilter2> filter2() {
		FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
		bean.addUrlPatterns("/*");
		bean.setOrder(0); // 낮은 번호가 필터중에서 가장먼저 실행됨
		return bean;
	}

}
