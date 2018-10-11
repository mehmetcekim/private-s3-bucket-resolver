package com.cekim.privates3bucketresolver.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Configuration
@EnableWebSecurity
public class LdapSecurity extends WebSecurityConfigurerAdapter {

	@Value("${spring.ldap.urls}")
	private String urls;
	
	@Value("${spring.ldap.username}")
	private String username;
	
	@Value("${spring.ldap.password}")
	private String password;
	
	@Value("${spring.ldap.base}")
	private String base;
	
	
    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http.httpBasic().and().authorizeRequests().anyRequest().authenticated().and().csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
    	  authenticationManagerBuilder.ldapAuthentication()
                .contextSource()
    	        .url(urls)
                .managerDn(username)
                .managerPassword(password)
                .and()
                .userSearchBase(base)
                .userSearchFilter("(cn={0})");
    }
}