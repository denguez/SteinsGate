package tech.zumaran.steinsgate;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
	
	@Value("${jwt.header}")
	private String header;
	
	@Value("${jwt.prefix}")
	private String prefix;
	
	@Value("${jwt.secret}")
	private String secret;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
			FilterChain chain) throws ServletException, IOException {
		
		String headerValue = request.getHeader(header);
		
		if(headerValue == null || !headerValue.startsWith(prefix)) {
			log.info("Invalid header {}", headerValue);
			chain.doFilter(request, response);
			return;
		}
		
		String token = headerValue.replace(prefix, "");
		try {
			Claims claims = Jwts.parser()
					.setSigningKey(secret.getBytes())
					.parseClaimsJws(token)
					.getBody();
			
			String email = claims.getSubject();
			
			if(email != null) {
				long contextId = (long) claims.get("id");
				
				@SuppressWarnings("unchecked")
				List<String> claimsAuthorities = (List<String>) claims.get("Authority");
				Set<GrantedAuthority> authorities = claimsAuthorities.stream()
						.map(a -> new SimpleGrantedAuthority(a))
						.collect(Collectors.toSet());
				
				UsernamePasswordAuthenticationToken auth = 
						new UsernamePasswordAuthenticationToken(email, null, authorities);
				
				SecurityContextHolder.getContext().setAuthentication(auth);
				
				request.setAttribute("contextId", contextId);
				
				log.info("User authenticated " + auth.getName() + " " 
						+ claimsAuthorities.stream().collect(Collectors.joining(", ")));
			}
		} catch (Exception e) {
			SecurityContextHolder.clearContext();
			log.info("Authentication exception. {}: {}", e.getClass().getSimpleName(), e.getMessage());
		}
		chain.doFilter(request, response);
	}
	
}

