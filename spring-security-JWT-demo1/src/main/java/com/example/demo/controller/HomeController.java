package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.config.JwtUtil;
import com.example.demo.model.AuthenitactionRequest;
import com.example.demo.model.AuthenticationResponse;
import com.example.demo.service.MyUserDetailService;

@RestController
public class HomeController {
	
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private MyUserDetailService userDetailsService;
	
	@Autowired
	private JwtUtil jwtutilToken;

	@GetMapping("/hello")
	public String getMessage() {
		return "Hello World";
	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> createAuthenticateToken(@RequestBody AuthenitactionRequest authRequest) throws Exception{
		try {
		authManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
		}
		catch(BadCredentialsException ex) {
			throw new Exception("Invalid Username and password",ex);
		}
		
		UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
		
		String jwt = jwtutilToken.generateToken(userDetails);
		
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}
}
