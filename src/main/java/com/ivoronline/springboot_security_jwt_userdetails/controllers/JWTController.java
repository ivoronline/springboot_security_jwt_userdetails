package com.ivoronline.springboot_security_jwt_userdetails.controllers;

import com.ivoronline.springboot_security_jwt_userdetails.utils.JWTUtil;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
public class JWTController {

  //PROPERTIES
  @Autowired JWTUtil               jwtUtil;
  @Autowired AuthenticationManager authenticationManager;

  //==================================================================
  // CREATE JWT
  //==================================================================
  // http://localhost:8080/CreateJWT?username=myuser&password=myuserpassword
  // eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdGllcyI6IltST0xFX0FETUlOLCBST0xFXJdIiwidXNlXVzZXIifQ.MshnOBSYQtLnm-QSv8
  @RequestMapping("CreateJWT")
  String createJWT(@RequestParam String username, @RequestParam String password) throws IOException {

    //AUTHENTICATE (COMPARE ENTERED AND STORED CREDENTIALS)
    Authentication authentication  = new UsernamePasswordAuthenticationToken(username, password);
                   authentication = authenticationManager.authenticate(authentication); //Exception

    //CREATE JWT
    String authorities = authentication.getAuthorities().toString(); //"[ROLE_ADMIN, ROLE_USER]"
    String jwt         = jwtUtil.createJWT(username, authorities);

    //RETURN JWT
    return jwt;

  }

  //==================================================================
  // AUTHENTICATE
  //==================================================================
  // http://localhost:8080/Authenticate?jwt=eyJhbGciOiJIUzI1NiJ9.eyJhdXRcm5WUiOiJteXVzZXIifQ.MshnONQtLnm-QSv8
  // authorization:Bearer <JWT>
  // {"authorities":"[ROLE_ADMIN, ROLE_USER]","username":"myuser"}
  @RequestMapping("Authenticate")
  String authenticate(
    @RequestParam (required = false) String jwt,
    @RequestHeader(required = false) String authorization
  ) throws Exception {

    //FOR AUTHORIZATION HEADER
    if(authorization!=null) { jwt = jwtUtil.getJWTFromAuthorizationHeader(authorization); }

    //CREATE AUTHENTICATION OBJECT
    Authentication authentication = jwtUtil.createAuthenticationObjectFromJWT(jwt);

    //STORE AUTHENTICATION INTO CONTEXT (SESSION)
    SecurityContextHolder.getContext().setAuthentication(authentication);

    //RETURN STATUS
    return "User Authenticated";

  }


  //==================================================================
  // GET CLAIMS
  //==================================================================
  // http://localhost:8080/GetClaims?jwt=eyJhbGciOiJIUzI1NiJ9.eyJhdXRST0xFX1VOiJteXVzZXIifQ.MshnOBNQtLnm-QSv8
  // authorization:Bearer <JWT>
  // {"authorities":"[ROLE_ADMIN, ROLE_USER]","username":"myuser"}
  @RequestMapping("GetClaims")
  Claims getClaims(
    @RequestParam (required = false) String jwt,
    @RequestHeader(required = false) String authorization
  ) throws Exception {

    //FOR AUTHORIZATION HEADER
    if(authorization!=null) { jwt = jwtUtil.getJWTFromAuthorizationHeader(authorization); }

    //GET CLAIMS
    Claims claims = jwtUtil.getClaims(jwt);

    //RETURN CLAIMS
    return claims;

  }

  //==================================================================
  // EXCEPTION HANDLER                             (For all Endpoints)
  //==================================================================
  @ExceptionHandler
  String exceptionHandler(Exception exception) {
    return exception.getMessage(); //Bad credentials
  }

}
