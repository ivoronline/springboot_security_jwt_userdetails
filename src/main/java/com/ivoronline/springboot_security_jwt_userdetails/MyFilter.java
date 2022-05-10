package com.ivoronline.springboot_security_jwt_userdetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
public class MyFilter implements Filter {

  //PROPERTIES
  @Autowired private JWTUtil jwtUtil;

  //==================================================================================
  // DO FILTER
  //==================================================================================
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterchain)
    throws IOException, ServletException {

    //CAST REQUEST TO GET ACCESS TO HEADERS
    HttpServletRequest httpRequest = (HttpServletRequest) request;

    //GET AUTHORIZATION HEADER
    String authorization = httpRequest.getHeader("Authorization");
    String jwt           = jwtUtil.getJWTFromAuthorizationHeader(authorization);

    //CREATE AUTHENTICATION OBJECT
    if(jwt != null) {
      Authentication authentication = jwtUtil.createAuthenticationObjectFromJWT(jwt);
      if (authentication != null) { SecurityContextHolder.getContext().setAuthentication(authentication); }
    }

    //CALL NEXT FILTER
    filterchain.doFilter(request, response);

  }

}
