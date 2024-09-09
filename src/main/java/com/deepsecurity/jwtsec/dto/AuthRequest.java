package com.deepsecurity.jwtsec.dto;

public record AuthRequest (
        String username,
        String password
){
}