package ma.enset.authenticatedservice.security.services;

import ma.enset.authenticatedservice.security.entities.AppRole;
import ma.enset.authenticatedservice.security.entities.AppUser;
import ma.enset.authenticatedservice.security.repositories.AppRoleRepository;
import ma.enset.authenticatedservice.security.repositories.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
@Service
@Transactional
public class AppServiceImpl implements IAppService{
    private AppRoleRepository appRoleRepository;
    private AppUserRepository appUserRepository;
    private PasswordEncoder passwordEncoder;

    public AppServiceImpl(AppRoleRepository appRoleRepository, AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appRoleRepository = appRoleRepository;
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser appUser) {
        String password = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(password));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppUser getUser(String userName) {
        return appUserRepository.findByUserName(userName);
    }

    @Override
    public AppUser addRoleToUser(String roleName, String userName) {
        AppUser user = appUserRepository.findByUserName(userName);
        AppRole role  = appRoleRepository.findByRoleName(roleName);
        user.getUserRoles().add(role);
        return user;
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public List<AppUser> userList() {
        return appUserRepository.findAll();
    }
}
