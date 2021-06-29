package com.example.demo.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.config.JwtUtil;
import com.example.demo.service.MyUserDetailService;

@Component
public class JwtRequestFilter extends OncePerRequestFilter{
	
	@Autowired
	JwtUtil jwtUtil;
	
	@Autowired
	MyUserDetailService userDetailService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authRequestHeader = request.getHeader("Authorization");
		
		String jwt=null;
		String username=null;
		
		if(authRequestHeader !=null && authRequestHeader.startsWith("Bearer ")){
			jwt = authRequestHeader.substring(7);
			username = jwtUtil.extractUsername(jwt);
		}
		
		if(username !=null && SecurityContextHolder.getContext().getAuthentication() == null) {
			
			UserDetails userDetail = userDetailService.loadUserByUsername(username);
			
			if(jwtUtil.validateToken(jwt, userDetail)) {
				UsernamePasswordAuthenticationToken userNamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetail,null,
						userDetail.getAuthorities());
				
				userNamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				SecurityContextHolder.getContext().setAuthentication(userNamePasswordAuthenticationToken);
				
			}
			
		}
		filterChain.doFilter(request, response);
	}

}
