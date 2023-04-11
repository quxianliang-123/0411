package com.example.swagger.controller;

import java.util.Map;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class SecurityAuthenticationProvider implements AuthenticationProvider {

	
    /**
     * 验证Authentication，建立系统使用者信息principal(token)
     */
    @Override
    public Authentication  authenticate(Authentication authentication) throws RuntimeException {
    	
    	Authentication authToken = SecurityContextHolder.getContext().getAuthentication();
    	Map<String, Object> attributes;
    	if (authToken instanceof OAuth2AuthenticationToken) {
    	    attributes = ((OAuth2AuthenticationToken) authToken).getPrincipal().getAttributes();
    	} else if (authToken instanceof JwtAuthenticationToken) {
    	    attributes = ((JwtAuthenticationToken) authToken).getTokenAttributes();
    	}
        //从token中获取用户信息
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;
        AccessToken accessToken = getAccessToken((token));
        KeycloakAuthenticationToken authenticationToken = new KeycloakAuthenticationToken(token.getAccount(), token.isInteractive());
        return authenticationToken;
    }

    private AccessToken getAccessToken(KeycloakAuthenticationToken principal) {
        KeycloakAuthenticationToken token = principal;
        KeycloakPrincipal keycloakPrincipal = (KeycloakPrincipal)token.getPrincipal();
        KeycloakSecurityContext context = keycloakPrincipal.getKeycloakSecurityContext();
        return context.getToken();
    }

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO 自動生成されたメソッド・スタブ
		return false;
	}

}
