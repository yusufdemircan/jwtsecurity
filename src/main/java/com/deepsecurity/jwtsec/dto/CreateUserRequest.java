package com.deepsecurity.jwtsec.dto;

import com.deepsecurity.jwtsec.model.Role;
import lombok.Builder;

import java.util.Set;


@Builder
public record CreateUserRequest(
        String name,
        String username,
        String password,
        Set<Role> authorities
){
}