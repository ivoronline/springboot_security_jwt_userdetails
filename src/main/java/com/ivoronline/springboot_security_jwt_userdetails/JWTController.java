package com.ivoronline.springboot_security_jwt_userdetails;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
public class JWTController {

  //PROPERTIES
  @Autowired JWTUtil               jwtUtil;
  @Autowired AuthenticationManager authenticationManager;

  //==================================================================
  // CREATE JWT
  //==================================================================
  // http://localhost:8080/CreateJWT?username=myuser&password=myuserpassword
  // eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdGllcyI6IltST0xFX0FETUlOLCBST0xFX1VTRVJdIiwidXNlcm5hbWUiOiJteXVzZXIifQ.MshnOBSYy6575qA2RBT4bisjIGmsuEUVNQtLnm-QSv8
  @RequestMapping("CreateJWT")
  String createJWT(@RequestParam String username, @RequestParam String password) {

    //AUTHENTICATE (COMPARE ENTERED AND STORED CREDENTIALS)
    Authentication enteredAuth  = new UsernamePasswordAuthenticationToken(username, password);
    Authentication returnedAuth = authenticationManager.authenticate(enteredAuth);  //AuthenticationException

    //CREATE JWT
    String authorities = returnedAuth.getAuthorities().toString(); //"[ROLE_ADMIN, ROLE_USER]"
    String jwt         = jwtUtil.createJWT(username, authorities);

    //RETURN JWT
    return jwt;

  }

  //==================================================================
  // GET CLAIMS
  //==================================================================
  // http://localhost:8080/GetClaims?jwt=eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdGllcyI6IltST0xFX0FETUlOLCBST0xFX1VTRVJdIiwidXNlcm5hbWUiOiJteXVzZXIifQ.MshnOBSYy6575qA2RBT4bisjIGmsuEUVNQtLnm-QSv8
  // authorization:Bearer <JWT>
  // {"authorities":"[ROLE_ADMIN, ROLE_USER]","username":"myuser"}
  @RequestMapping("GetClaims")
  Claims getClaims(
    @RequestParam (required = false) String jwt,
    @RequestHeader(required = false) String authorizationHeader
  ) throws Exception {

    //LOCATE JWT
    if     (jwt                 != null) {  } //Proceed with the code
    else if(authorizationHeader != null) { jwt = jwtUtil.getJWTFromAuthorizationHeader(authorizationHeader); }
    else   { throw new Exception("No JWT present in HTTP Request Parameter or Authorization Header"); }

    //GET CLAIMS
    Claims claims = jwtUtil.getClaims(jwt);

    //RETURN CLAIMS
    return claims;

  }

  //==================================================================
  // AUTHENTICATE
  //==================================================================
  // http://localhost:8080/Authenticate?jwt=eyJhbGciOiJIUzI1NiJ9.eyJhdXRob3JpdGllcyI6IltST0xFX0FETUlOLCBST0xFX1VTRVJdIiwidXNlcm5hbWUiOiJteXVzZXIifQ.MshnOBSYy6575qA2RBT4bisjIGmsuEUVNQtLnm-QSv8
  // authorization:Bearer <JWT>
  // {"authorities":"[ROLE_ADMIN, ROLE_USER]","username":"myuser"}
  @RequestMapping("Authenticate")
  String authenticate(
    @RequestHeader(required = false) String authorizationHeader,
    @RequestParam (required = false) String jwt
  ) throws Exception {

    //LOCATE JWT
    if     (jwt                 != null) {  } //Proceed with the code
    else if(authorizationHeader != null) { jwt = jwtUtil.getJWTFromAuthorizationHeader(authorizationHeader); }
    else   { throw new Exception("No JWT present in HTTP Request Parameter or Authorization Header"); }

    //GET AUTHENTICATION OBJECT (with Authorities)
    Authentication authentication = jwtUtil.createAuthenticationObjectFromJWT(jwt);

    //CHECK RETURNED AUTHENTICATION OBJECT
    if (authentication == null) { throw new Exception("Authentication failed"); }

    //STORE AUTHENTICATION INTO CONTEXT (SESSION)
    SecurityContextHolder.getContext().setAuthentication(authentication);

    //RETURN CLAIMS
    return "Authentication successful";

  }

  //==================================================================
  // EXCEPTION HANDLER                             (For all Endpoints)
  //==================================================================
  @ExceptionHandler
  String exceptionHandler(Exception exception) {
    return exception.getMessage(); //Bad credentials
  }

}
