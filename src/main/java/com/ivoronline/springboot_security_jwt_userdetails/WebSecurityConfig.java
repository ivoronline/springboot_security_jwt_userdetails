package com.ivoronline.springboot_security_jwt_userdetails;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  //========================================================================
  // CONFIGURE
  //========================================================================
  @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity.authorizeRequests().antMatchers("/GetJWT").permitAll();
    httpSecurity.formLogin();
  }

  //=================================================================
  // AUTHENTICATION MANAGER BEAN                      (For CreateJWT)
  //=================================================================
  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  //========================================================================
  // USER DETAILS SERVICE BEAN
  //========================================================================
  @Bean
  @Override
  public UserDetailsService userDetailsServiceBean() throws Exception {

    //CREATE USERS
    UserDetails myuser  = User.withUsername("myuser" ).password("myuserpassword" ).roles("USER", "ADMIN").build();

    //LOAD USERS
    return new InMemoryUserDetailsManager(myuser);

  }

  //========================================================================
  // PASSWORD ENCODER
  //========================================================================
  @Bean
  PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

}
