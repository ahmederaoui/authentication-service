package ma.enset.authenticatedservice.security.services;

import ma.enset.authenticatedservice.security.entities.AppRole;
import ma.enset.authenticatedservice.security.entities.AppUser;

import java.util.List;

public interface IAppService {
    AppUser addNewUser(AppUser appUser);
    AppUser getUser(String userName);
    AppUser addRoleToUser(String roleName, String UserName);
    AppRole addNewRole(AppRole appRole);
    List<AppUser> userList();

}
