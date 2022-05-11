package com.ivoronline.springboot_security_jwt_userdetails.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JWTUtil {

  //USED TO CREATE & DECODE JWT
  public final static String SECRET_KEY = "mysecretkey";

  //========================================================================
  // CREATE JWT
  //========================================================================
  // createJWT("myuser", "USER")
  // eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiW1JPTEVfVVNFUl0iLCJ1c2VybmFtZSI6Im15dXNlciJ9.owfUJ4dy06L7aDSYRJRC4WyMAgUH0F8JmPIISnATwkg
  public String createJWT(String username, String authorities) throws IOException {

    //CHECK INPUT PARAMETERS
    if(username   ==null) { throw new IOException("Can't create JWT without username"   ); }
    if(authorities==null) { throw new IOException("Can't create JWT without authorities"); }

    //PAYLOAD (SPECIFY CLAIMS)
    Map<String, Object> claims = new HashMap<>();
                        claims.put("username"   , username);
                        claims.put("authorities", authorities);

    //SIGNATURE (SPECIFY ALGORITHM & SECRET KEY)
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    byte[]             keyBytes           = DatatypeConverter.parseBase64Binary(SECRET_KEY);
    Key                key                = new SecretKeySpec(keyBytes, signatureAlgorithm.getJcaName());

    //BUILD JWT
    String jwt = Jwts.builder()
      .setClaims(claims)
      .signWith(signatureAlgorithm, key)
      .compact();

    //RETURN JWT
    return jwt;

  }

  //========================================================================
  // GET CLAIMS
  //========================================================================
  public Claims getClaims(String jwt) {

    //GET CLAIMS
    Claims claims = Jwts.parser()
      .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
      .parseClaimsJws(jwt)
      .getBody();

    //RETURN CLAIMS
    return claims;

  }

  //==================================================================================
  // GET JWT FROM AUTHORIZATION HEADER
  //==================================================================================
  // authorization:Bearer <JWT>
  public String getJWTFromAuthorizationHeader(String authorizationHeader) throws IOException {

    //CHECK INPUT PARAMETERS
    if( authorizationHeader == null)               { throw new IOException("No Authorization Header"); }
    if(!authorizationHeader.startsWith("Bearer ")) { throw new IOException("No Bearer"              ); }

    //GET JWT
    String jwt = authorizationHeader.replace("Bearer ", ""); //Remove Bearer suffix

    //RETURN JWT
    return jwt;

  }

  //==================================================================================
  // CREATE AUTHENTICATION OBJECT FROM JWT
  //==================================================================================
  // {"authorities":"[ROLE_ADMIN, ROLE_USER]","username":"myuser"}
  public Authentication createAuthenticationObjectFromJWT(String jwt) throws IOException {

    //CHECK INPUT PARAMETERS
    if(jwt == null) { throw new IOException("No JWT"); }

    //GET CLAIMS
    Claims claims      = getClaims(jwt);
    String username    = (String) claims.get("username");     System.out.println(username);
    String authorities = (String) claims.get("authorities");  System.out.println(authorities);

    //CHECK CLAIMS
    if(username   ==null) { throw new IOException("JWT doesn't contain username"   ); }
    if(authorities==null) { throw new IOException("JWT doesn't contain authorities"); }

    //CREATE AUTHORITIES
    String                 authoritiesString = authorities.replace("[","").replace("]","").replace(" ","");
    String[]               authoritiesArray  = authoritiesString.split(",");
    List<GrantedAuthority> authoritiesList   = new ArrayList<GrantedAuthority>();
    for(String authority : authoritiesArray) {
      authoritiesList.add(new SimpleGrantedAuthority(authority));
    }

    //CREATE VALIDATED AUTHENTICATION
    Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authoritiesList);

    //RETURN VALIDATED AUTHENTICATION
    return authentication;

  }

}


