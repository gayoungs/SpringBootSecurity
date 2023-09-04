package com.coding404.demo.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.coding404.demo.user.MyUserDetailService;

@Configuration //설정파일
@EnableWebSecurity //이 설정파일을 시큐리티 필터에 추가
@EnableGlobalMethodSecurity(prePostEnabled = true) // 어노테이션으로 권한을 지정할 수 있게 함
public class SecurityConfig {
	
	//나를기억해에서 사용할 UserDetailService
	@Autowired
	private MyUserDetailService myUserDetailService;
	
	
	
	//비밀번호 암호화객체
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	
	@Bean
	public SecurityFilterChain securityFilter(HttpSecurity http) throws Exception {
		//csrf토큰 x
		http.csrf().disable();
		
		//권한설정
		//http.authorizeHttpRequests( authorize -> authorize.anyRequest().permitAll() );
		
		//모든페이지에 대해서 거부
		//http.authorizeHttpRequests( authorize -> authorize.anyRequest().denyAll() );
		
		//user페이지에 대해서 인증이 필요
//		http.authorizeHttpRequests( authorize -> authorize.
//												 antMatchers("/user/**").
//												 authenticated() );
		
		//user페이지에 대해서 권한이 필요
		//http.authorizeHttpRequests( authorize -> authorize.antMatchers("/user/**").hasRole("USER") );
		
		//user페이지는 user권한이 필요, admin페이지는 admin권한이 필요
//		http.authorizeHttpRequests( authorize -> authorize.antMatchers("/user/**").hasRole("USER")
//														  .antMatchers("/admin/**").hasRole("ADMIN") );
		
		// all페이지는 인증만 되면 됨, user페이지는 user권한, admin페이지는 admin권한, 나머지 모든 페이지는 접근이 가능함.
//		http.authorizeHttpRequests( authorize -> authorize.antMatchers("/all").authenticated()
//														  .antMatchers("/user/**").hasRole("USER")
//														  .antMatchers("/admin/**").hasRole("ADMIN")
//														  .anyRequest().permitAll() );
		
		// all페이지는 인증만 되면 됨, user페이지는 3중 1개의 권한을 가지면 됨, ......
		//권한 앞에는 ROLE_ 가 자동으로 생략이 됩니다.
		http.authorizeHttpRequests( authorize -> authorize.antMatchers("/all").authenticated()
												  .antMatchers("/user/**").hasAnyRole("USER", "ADMIN", "TESTER")
												  .antMatchers("/admin/**").hasRole("ADMIN")
												  .anyRequest().permitAll() );

		
		//시큐리티 설정파일 만들면, 시큐리티가 제공하는 기본 로그인페이지가 보이지 않게됩니다.
		//시큐리티가 사용하는 기본로그인페이지를 사용함
		//권한 or 인증이 되지 않으면 기본으로 선언된 로그인페이지를 보여주게 됩니다.
		//http.formLogin( Customizer.withDefaults() ); //기본로그인페이지사용
		
		//사용자가 제공하는 폼기반 로그인기능을 사용할수 있습니다.
		http.formLogin()
			.loginPage("/login") //로그인화면
			.loginProcessingUrl("/loginForm")//로그인시도 요청경로 -> 스프링이 로그인 시도를 낚아채서 UserDetailService객체로 연결
			.defaultSuccessUrl("/all") //로그인 성공시 페이지
			.failureUrl("/login?err=true") //로그인 실패시 이동할 url
			.and()
			.exceptionHandling().accessDeniedPage("/deny") //권한이 없을 때 이동할 리다이렉트 경로
			.and()
			.logout().logoutUrl("/logout").logoutSuccessUrl("/hello"); //default로그아웃 경로 /logout, /logout아웃 주소를 직접 작성할 수 있고, 로그아웃성공시 리다이렉트할 경로
			
		//나를기억해
		http.rememberMe()
			.key("coding404") //토큰(쿠키) 를 만들 비밀키 (필수)
			.rememberMeParameter("remember-me") //화면에서 전달받는 checked name명입니다. (필수)
			.tokenValiditySeconds(60) //쿠키(토큰)의 유효시간 (필수)
			.userDetailsService(myUserDetailService) //토큰이 있을 때 실행시킬 userDetailService객체 (필수)
			.authenticationSuccessHandler( customRememberMe() ); //나를기억해가 동작할 때, 실행할 핸들러객체를 넣습니다.
		
		
		return http.build();
	}
	
	//customeRememberMe
	@Bean
	public CustomRememberMe customRememberMe() {
		CustomRememberMe me = new CustomRememberMe("/all"); //리멤버미 성공시 실행시킬 리다이렉트 주소
		return me;
	}
	
	
	
	
	
	
	
	
	
	
	
	
}
