package ma.enset.authenticatedservice;

import ma.enset.authenticatedservice.security.entities.AppRole;
import ma.enset.authenticatedservice.security.entities.AppUser;
import ma.enset.authenticatedservice.security.services.AppServiceImpl;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
//@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class AuthenticatedServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthenticatedServiceApplication.class, args);
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner commandLineRunner(AppServiceImpl appService){
        return args -> {
            appService.addNewRole(new AppRole(null,"USER"));
            appService.addNewRole(new AppRole(null,"ADMIN"));
            appService.addNewRole(new AppRole(null,"RESPONSABLE"));
            appService.addNewRole(new AppRole(null,"MANAGER"));
            appService.addNewRole(new AppRole(null,"FINANCIER"));

            appService.addNewUser(new AppUser(null,"eraoui","eraoui",new ArrayList<>()));
            appService.addNewUser(new AppUser(null,"el hanafi","el hanafi",new ArrayList<>()));
            appService.addNewUser(new AppUser(null,"nedday","nedday",new ArrayList<>()));
            appService.addNewUser(new AppUser(null,"mansouri","mansouri",new ArrayList<>()));

            appService.addRoleToUser("USER","eraoui");
            appService.addRoleToUser("ADMIN","eraoui");
            appService.addRoleToUser("RESPONSABLE","el hanafi");
            appService.addRoleToUser("MANAGER","el hanafi");
            appService.addRoleToUser("RESPONSABLE","nedday");
            appService.addRoleToUser("USER","nedday");
            appService.addRoleToUser("FINANCIER","mansouri");


        };
    }
}
