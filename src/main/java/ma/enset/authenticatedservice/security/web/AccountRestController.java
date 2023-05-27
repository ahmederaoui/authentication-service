package ma.enset.authenticatedservice.security.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import ma.enset.authenticatedservice.security.JWTUtil;
import ma.enset.authenticatedservice.security.entities.AppRole;
import ma.enset.authenticatedservice.security.entities.AppUser;
import ma.enset.authenticatedservice.security.repositories.AppRoleRepository;
import ma.enset.authenticatedservice.security.services.IAppService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    private IAppService appService;

    public AccountRestController(IAppService appService) {
        this.appService = appService;
    }
    @GetMapping(path = "/users")
//    @PostAuthorize("hasAnyAuthority('USER')")
    public List<AppUser> getAllUsers(){
        return appService.userList();
    }
    @GetMapping("/users/{userName}")
    public AppUser getUser(@PathVariable String userName){
        return appService.getUser(userName);
    }
    @PostMapping("/users")
//    @PostAuthorize("hasAnyAuthority('ADMIN')")
    public AppUser addUser(@RequestBody AppUser user){
        return appService.addNewUser(user);
    }
    @PostMapping("/roles")
    public AppRole addRole(@RequestBody AppRole role){
        return appService.addNewRole(role);
    }
    @PostMapping("/formUserRole")
    public AppUser addRoleUser( String role, Principal principal){
        System.out.println(principal.getName());
        return appService.addRoleToUser(role,principal.getName());
    }
    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String authorizationToken = request.getHeader(JWTUtil.AUTH_HEADER);
        if(authorizationToken!=null && authorizationToken.startsWith(JWTUtil.PREFIX)) {
            try {
                String jwt = authorizationToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String userName = decodedJWT.getSubject();
                AppUser appUser = appService.getUser(userName);
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getUserRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> idToken = new HashMap<>();
                idToken.put("access-token", jwtAccessToken);
                idToken.put("refresh-token", jwt);
                response.setContentType("application/json");
                response.setHeader(JWTUtil.AUTH_HEADER, jwtAccessToken);
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);

            } catch (Exception e) {
                throw e;
            }
        }else {
            throw new RuntimeException("refresh token required");
        }
    }
}
@Data
class FormUserRole{
    private String userName;
    private String roleName;
}
