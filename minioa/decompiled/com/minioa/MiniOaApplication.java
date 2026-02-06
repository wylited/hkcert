/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.MiniOaApplication
 *  org.springframework.boot.SpringApplication
 *  org.springframework.boot.autoconfigure.SpringBootApplication
 */
package com.minioa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MiniOaApplication {
    public static void main(String[] args) {
        SpringApplication.run(MiniOaApplication.class, (String[])args);
        System.out.println("\n========================================");
        System.out.println("Mini-OA \u529e\u516c\u7ba1\u7406\u7cfb\u7edf\u542f\u52a8\u6210\u529f\uff01");
        System.out.println("========================================\n");
    }
}

