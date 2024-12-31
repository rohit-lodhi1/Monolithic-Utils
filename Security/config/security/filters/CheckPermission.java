package com.gramseva.config.security.filters;

import com.gramseva.model.PermissionTitle;
import com.gramseva.model.PermissionType;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface CheckPermission {
    PermissionTitle permission();
    PermissionType permissionType();// Permission name required to access the endpoint
}
