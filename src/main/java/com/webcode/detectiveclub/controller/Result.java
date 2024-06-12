package com.webcode.detectiveclub.controller;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Result {
    private String message;
    private boolean isTrusted;
}
