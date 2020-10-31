package tech.zumaran.steinsgate;

import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private JWTAuthenticationFilter jwtFilter;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors()
		.and()
		.csrf()
			.disable()
		.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS) 	
		.and()
		.exceptionHandling()
			.authenticationEntryPoint((req, res, e) -> {
				res.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
			}) 				
		.and()
		.addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class)
		.authorizeRequests()
			.antMatchers(HttpMethod.POST, "/navi/**").permitAll()
			.anyRequest().authenticated(); 
  	}
	
	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
    	final var config = new CorsConfiguration();
    	config.setAllowedOrigins(List.of("*"));
    	config.setAllowedMethods(List.of("HEAD", "GET", "POST", "PUT", "DELETE"));
        config.setAllowCredentials(true);
        config.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type", "Connection"));
        
        final var src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", config);
        return src;
    }
	
}