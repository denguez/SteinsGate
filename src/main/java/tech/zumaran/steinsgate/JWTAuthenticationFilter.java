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

import com.google.common.base.Optional;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
	
	@Value("${jwt.header}")
	private String header;
	
	@Value("${jwt.prefix}")
	private String prefix;
	
	@Value("${jwt.secret}")
	private String secret;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) 
			throws ServletException, IOException {
		try {
			final var maybeToken = parseToken(request.getHeader(header));
			if (maybeToken.isPresent()) {
				final var token = maybeToken.get();
				SecurityContextHolder.getContext().setAuthentication(token);
				request.setAttribute("contextId", token.getDetails());
			}
		} catch(Exception e) {
			SecurityContextHolder.clearContext();
		} finally {
			chain.doFilter(request, response);
		}
	}
	
	private Optional<UsernamePasswordAuthenticationToken> parseToken(String header) {
		if (header != null && header.startsWith(prefix)) {
			Claims claims = Jwts.parser()
					.setSigningKey(secret.getBytes())
					.parseClaimsJws(header.replace(prefix, ""))
					.getBody();
				
			var auths = parseAuthorities(claims.get("Authority"));
			var token = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, auths);
			token.setDetails(claims.get("id"));
			return Optional.of(token);
		} 
		return Optional.absent();
	}
	
	@SuppressWarnings("unchecked")
	private static Set<GrantedAuthority> parseAuthorities(Object authorities) {
		return ((List<String>) authorities).stream()
				.map(a -> new SimpleGrantedAuthority(a))
				.collect(Collectors.toSet());
	}

}

