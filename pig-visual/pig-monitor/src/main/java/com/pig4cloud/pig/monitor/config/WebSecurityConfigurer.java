/*
 * Copyright (c) 2020 pig4cloud Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pig4cloud.pig.monitor.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.UUID;

import static io.undertow.util.Methods.POST;
import static org.springframework.http.HttpMethod.DELETE;

/**
 * WebSecurityConfigurer
 *
 * @author lishangbu
 * @date 2019/2/1
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer {

	// @Value("${spring.security.user.name}")
	// private String username;
	//
	// @Value("${spring.security.user.password}")
	// private String password;

	private final String adminContextPath;

	public WebSecurityConfigurer(AdminServerProperties adminServerProperties) {
		this.adminContextPath = adminServerProperties.getContextPath();
	}

	/**
	 * spring security 默认的安全策略
	 * @param http security注入点
	 * @return SecurityFilterChain
	 * @throws Exception
	 */
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		successHandler.setTargetUrlParameter("redirectTo");
		successHandler.setDefaultTargetUrl(adminContextPath + "/");
		//
		// http.headers().frameOptions().disable().and().authorizeRequests()
		// .requestMatchers(adminContextPath + "/assets/**", adminContextPath + "/login",
		// adminContextPath + "/actuator/**")
		// .permitAll().dispatcherTypeMatchers(DispatcherType.ASYNC).permitAll().anyRequest().authenticated().and()
		// .formLogin().loginPage(adminContextPath +
		// "/login").successHandler(successHandler).and().logout()
		// .logoutUrl(adminContextPath +
		// "/logout").and().httpBasic().and().csrf().disable();
		http.authorizeHttpRequests((authorizeRequests) -> authorizeRequests //
				.requestMatchers(new AntPathRequestMatcher(adminContextPath + "/assets/**")).permitAll()
				.requestMatchers(new AntPathRequestMatcher(adminContextPath + "/variables.css")).permitAll()
				.requestMatchers(new AntPathRequestMatcher(adminContextPath + "/actuator/info")).permitAll()
				.requestMatchers(new AntPathRequestMatcher(adminContextPath + "/actuator/health")).permitAll()
				.requestMatchers(new AntPathRequestMatcher(adminContextPath + "/login")).permitAll()
				.dispatcherTypeMatchers(DispatcherType.ASYNC).permitAll() // https://github.com/spring-projects/spring-security/issues/11027
				.anyRequest().authenticated())
				.formLogin(
						(formLogin) -> formLogin.loginPage(adminContextPath + "/login").successHandler(successHandler))
				.logout((logout) -> logout.logoutUrl(adminContextPath + "/logout"))
				.httpBasic(Customizer.withDefaults());

		http.addFilterAfter(new CustomCsrfFilter(), BasicAuthenticationFilter.class)
				.csrf((csrf) -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
						.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()).ignoringRequestMatchers(
								new AntPathRequestMatcher(adminContextPath + "/instances", POST.toString()),
								new AntPathRequestMatcher(adminContextPath + "/instances/*", DELETE.toString()),
								new AntPathRequestMatcher(adminContextPath + "/actuator/**")));

		http.rememberMe((rememberMe) -> rememberMe.key(UUID.randomUUID().toString()).tokenValiditySeconds(1209600));
		return http.build();
	}

	// @Bean
	// public UserDetailsService userDetailsService() {
	// UserDetails user =
	// User.withDefaultPasswordEncoder().username(username).password(password).roles("USER")
	// .build();
	//
	// return new InMemoryUserDetailsManager(user);
	// }
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().requestMatchers("/js/**", "/images/**");
	}

}
