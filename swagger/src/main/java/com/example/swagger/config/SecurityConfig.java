package com.example.swagger.config;

import org.keycloak.adapters.springsecurity.authentication.KeycloakLogoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

//@Configuration
//@EnableWebSecurity
//class SecurityConfig {
//
//	private final KeycloakLogoutHandler keycloakLogoutHandler;
//
//	SecurityConfig(KeycloakLogoutHandler keycloakLogoutHandler) {
//		this.keycloakLogoutHandler = keycloakLogoutHandler;
//	}
//
//	@Bean
//	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
//		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
//	}
//
//	@Bean
//	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//		http.cors()
//				.and()
//				// 预防攻击：关闭
//				.csrf().disable();
//		http.authorizeRequests()
//				.antMatchers("/**")
//				.permitAll()
//				.anyRequest();
//		http.oauth2Login()
//				.and()
//				.logout()
//				.addLogoutHandler(keycloakLogoutHandler)
//				.logoutSuccessUrl("/");
//		//		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//		return http.build();
//	}
//
//	@Bean
//	public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
//		return http.getSharedObject(AuthenticationManagerBuilder.class)
//				.build();
//	}
//}
//
//@KeycloakConfiguration
//@EnableGlobalMethodSecurity(prePostEnabled=true)
//public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
//
//    @Autowired
//    private SecurityAuthenticationProvider authenticationProvider;
//
//    @Autowired
//    private KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter;
//
//    @Autowired
//    private KeycloakPreAuthActionsFilter keycloakPreAuthActionsFilter;
//
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(authenticationProvider);
//    }
//
//    @Bean
//    public KeycloakConfigResolver keycloakConfigResolver() {
//        return new KeycloakSpringBootConfigResolver();
//    }
//
//    @Bean
//    public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
//            KeycloakAuthenticationProcessingFilter filter) {
//        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//        registrationBean.setEnabled(true);
//        return registrationBean;
//    }
//
//    @Bean
//    public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
//            KeycloakPreAuthActionsFilter filter) {
//        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//        registrationBean.setEnabled(true);
//        return registrationBean;
//    }
//
//    @Bean
//    @Override
//    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
//        return new NullAuthenticatedSessionStrategy();
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//
//        http.anyRequest().permitAll();
//    	
//        http.authorizeRequests()
//        .antMatchers("/*")
//        .permitAll();
//        
//        http
//                //.addFilterBefore(mySecurityInterceptor, FilterSecurityInterceptor.class)
//                .addFilterBefore(keycloakAuthenticationProcessingFilter, FilterSecurityInterceptor.class)
//                .addFilterBefore(keycloakPreAuthActionsFilter, KeycloakAuthenticationProcessingFilter.class);
//    }
//}

//@Configuration
//public class SecurityConfig {
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		http
//				.authorizeRequests()
//				.mvcMatchers("/fake-login").permitAll() // 将/fake-login设置为白名单
//				.anyRequest().authenticated() // 其他请求需要认证
//				.and()
//				.oauth2Login() // 启用OAuth2登录
//				.loginPage("/fake-login");
//
//		return http.build();
//	}
//}

@Configuration
@EnableWebSecurity
class SecurityConfig {

	private final KeycloakLogoutHandler keycloakLogoutHandler;

	SecurityConfig(KeycloakLogoutHandler keycloakLogoutHandler) {
		this.keycloakLogoutHandler = keycloakLogoutHandler;
	}

	@Bean
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/*")
				.hasRole("USER")
				.anyRequest()
				.permitAll();
		//		http.oauth2Login()
		//				.and()
		//				.logout()
		//				.addLogoutHandler(keycloakLogoutHandler)
		//				.logoutSuccessUrl("/");
		//		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		return http.build();
	}
}
