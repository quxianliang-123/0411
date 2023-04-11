package com.example.swagger.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@SpringBootApplication
public class KeycloakDemoController {

	private static String authorizationRequestBaseUri = "oauth2/authorization";
	Map oauth2AuthenticationUrls = new HashMap<>();

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	//	
	//    @Autowired
	//    private SecurityAuthenticationProvider securityAuthenticationProvider;

	@Autowired
	private KeycloakClient KeycloakClient;
	//
	//	@GetMapping(path = "/fake-login")
	//	public String customers(@RequestBody Map<String, Object> requestBody) {

	@GetMapping(value = "/fake-login")
	public String customers(Model model) {

		//		Authentication authToken = SecurityContextHolder.getContext().getAuthentication();
		//		Map<String, Object> attributes = new HashMap<>();
		//		//		if (authToken instanceof OAuth2AuthenticationToken) {
		//		try {
		//			attributes = ((OAuth2AuthenticationToken) authToken).getPrincipal().getAttributes();
		//		} catch (Exception e) {
		//
		//			e.getMessage();
		//		}
		//
		//		String a = attributes.get("preferred_username").toString();
		//
		//		System.out.println(a);

		//		} else if (authToken instanceof JwtAuthenticationToken) {
		//			attributes = ((JwtAuthenticationToken) authToken).getTokenAttributes();
		//		}

		//		 String response = getAccessToken();
		//		 System.out.println(response);

		//		String userId = (String) requestBody.get("userId");
		//
		//		System.out.println(userId);
		//
		//		KeycloakClient.excute();

		return "fake-login";
	}

	//	@Autowired
	//	private RestTemplate restTemplate;

	//	@GetMapping("/tologinpage")
	//	public String toprocessLogin(Model model) {
	//		model.addAttribute("userSearchRequest", new UserSearchRequest());
	//		return "login";
	//	}

	//	@GetMapping("/testGetApi")
	//	public String getJson() {
	//		String url = "http://localhost:8080/realms/SpringBootKeycloak/protocol/openid-connect/token";

	//		HttpHeaders headers = new HttpHeaders();
	//        headers.set("Authorization", "Bearer {token}");
	//		ResponseEntity<String> results = restTemplate.exchange(url, HttpMethod.GET, map, String.class);
	//		String json = results.getBody();

	//		 String response = getAccessToken();

	//		
	//
	//		return response;

}
//
//	@PostMapping("/loginfunction")
//	public String processLogin(@ModelAttribute UserSearchRequest userSearchRequest, Model model) {
//
//		model.addAttribute(user);
//		return "home";
//
//	}

//}
