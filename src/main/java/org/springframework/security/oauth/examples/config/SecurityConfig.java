package org.springframework.security.oauth.examples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
				.passwordEncoder(new BCryptPasswordEncoder())
				.withUser("marissa").password("$2a$10$6MxuRwvl.qMTiSbDhqYrPeA2fOwUSxc3vn.myIh5CKYWoKdYPtSGa").roles("USER")
				.and()
				.withUser("sam").password("$2a$10$z4PVz9gUnr96PlduZK7MHeTUQLslVf3qefRcdN9wAKzGqgoVUuc0q").roles("USER");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
    	    http.authorizeRequests()
                .antMatchers("/sparklr/**","/facebook/**").hasRole("USER")
                .anyRequest().permitAll()
                .and()
            .logout()
                .logoutSuccessUrl("/login.jsp")
                .permitAll()
                .and()
            .formLogin()
            	.loginProcessingUrl("/login")
                .loginPage("/login.jsp")
                .failureUrl("/login.jsp?authentication_error=true")
                .permitAll();
    	// @formatter:on
	}

}
