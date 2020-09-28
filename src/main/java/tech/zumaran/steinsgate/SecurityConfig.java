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

import lombok.extern.slf4j.Slf4j;

@Slf4j
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private JWTAuthenticationFilter jwtFilter;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.csrf().disable()
		.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS) 	
		.and()
		.exceptionHandling()
			.authenticationEntryPoint((req, resp, e) -> {
				resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				log.info(e.getMessage());
			}) 				
		.and()
		.addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class)
		.authorizeRequests()
			.antMatchers(HttpMethod.POST, "/navi/**").permitAll()
			.anyRequest().authenticated(); 
  	}
	
	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
    	final CorsConfiguration configuration = new CorsConfiguration();
    	configuration.setAllowedOrigins(List.of("*"));
    	configuration.setAllowedMethods(List.of("HEAD", "GET", "POST", "PUT", "DELETE"));
        // setAllowCredentials(true) is important, otherwise:
        // The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.
        configuration.setAllowCredentials(true);
        // setAllowedHeaders is important! Without it, OPTIONS preflight request
        // will fail with 403 Invalid CORS request
        configuration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type", "Connection"));
        
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
	
}