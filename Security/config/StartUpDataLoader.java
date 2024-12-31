package com.gramseva.config;

import com.gramseva.model.Role;
import com.gramseva.model.RoleType;
import com.gramseva.model.User;
import com.gramseva.repository.RoleRepository;
import com.gramseva.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class StartUpDataLoader implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        ch.qos.logback.classic.LoggerContext loggerContext = (ch.qos.logback.classic.LoggerContext) org.slf4j.LoggerFactory.getILoggerFactory();
        loggerContext.stop();
        this.addRoles();
        if (userRepository.findByEmailAndIsDeleted("rohitd.dollop@gmail.com",Boolean.FALSE).isEmpty()) {
            User user = new User();
            user.setPassword(passwordEncoder.encode("12345"));
            user.setIsActive(true);
            user.setContactNumber("6263703637");
            user.setEmail("rohitd.dollop@gmail.com");
            user.setIsDeleted(false);
            this.userRepository.save(user);
        }
    }

    public void addRoles() {
        if (this.roleRepository.findByRoleName(RoleType.ADMIN.getKey()).isEmpty()) {
            Role role = new Role();
            role.setRoleName(RoleType.ADMIN.getKey());
            role.setType(RoleType.ADMIN);
            role.setDescription("This is Admin");
            role.setIsActive(true);
            this.roleRepository.save(role);
        }
    }
}
