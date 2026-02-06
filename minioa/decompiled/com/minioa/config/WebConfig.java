/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.config.WebConfig
 *  com.minioa.interceptor.LoginInterceptor
 *  org.springframework.context.annotation.Configuration
 *  org.springframework.web.servlet.HandlerInterceptor
 *  org.springframework.web.servlet.config.annotation.InterceptorRegistry
 *  org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry
 *  org.springframework.web.servlet.config.annotation.WebMvcConfigurer
 */
package com.minioa.config;

import com.minioa.interceptor.LoginInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig
implements WebMvcConfigurer {
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor((HandlerInterceptor)new LoginInterceptor()).addPathPatterns(new String[]{"/**"}).excludePathPatterns(new String[]{"/login", "/register", "/doLogin", "/doRegister", "/partner/**", "/css/**", "/js/**", "/avatars/**", "/.git/**", "/error"});
    }

    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler(new String[]{"/avatars/**"}).addResourceLocations(new String[]{"file:uploads/avatars/"});
        registry.addResourceHandler(new String[]{"/.git/**"}).addResourceLocations(new String[]{"classpath:/static/git/"});
    }
}

