package com.gramseva.config.security.filters;

import com.gramseva.exception.ForbiddenException;
import com.gramseva.model.PermissionTitle;
import com.gramseva.model.PermissionType;
import com.gramseva.model.Role;
import com.gramseva.repository.RoleRepository;
import com.gramseva.service.IPermissionService;
import com.gramseva.utils.Constants;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Aspect
@Component
public class PermissionAspect {

    @Autowired
    private IPermissionService permissionService;

    @Autowired
    private RoleRepository roleRepository;

    @Before("@annotation(checkPermission)")
    public void checkUserPermission(CheckPermission checkPermission) {

        if (!hasPermission(checkPermission.permission(), checkPermission.permissionType())) {
            throw new ForbiddenException(Constants.ACCESS_DENIED);
        }
    }

    private boolean hasPermission(PermissionTitle permission, PermissionType type) {
        // Gets the role from the security context
        String roleName = SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().map(GrantedAuthority::getAuthority)  // Convert each authority to its name
                .toList().get(0);

        Optional<Role> role = this.roleRepository.findByRoleName(roleName);
        return role.filter(value -> permissionService.hasPermission(value, permission, type)).isPresent();
    }
}
