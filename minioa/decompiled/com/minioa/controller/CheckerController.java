/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.controller.CheckerController
 *  javax.servlet.http.HttpServletRequest
 *  org.springframework.web.bind.annotation.GetMapping
 *  org.springframework.web.bind.annotation.RequestMapping
 *  org.springframework.web.bind.annotation.RestController
 */
package com.minioa.controller;

import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value={"/checker"})
public class CheckerController {
    @GetMapping(value={"/remote"})
    public String remoteAddr(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}

