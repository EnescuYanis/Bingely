package com.bingely.backend.dto;

public record LoginRequest(
        String usernameOrEmail,
        String password
) {}