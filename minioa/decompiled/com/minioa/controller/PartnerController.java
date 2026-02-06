/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.alibaba.seckit.SecurityUtil
 *  com.minioa.controller.PartnerController
 *  org.springframework.stereotype.Controller
 *  org.springframework.web.bind.annotation.GetMapping
 *  org.springframework.web.bind.annotation.PostMapping
 *  org.springframework.web.bind.annotation.RequestMapping
 *  org.springframework.web.bind.annotation.RequestParam
 *  org.springframework.web.bind.annotation.ResponseBody
 */
package com.minioa.controller;

import com.alibaba.seckit.SecurityUtil;
import java.sql.DriverManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping(value={"/partner"})
public class PartnerController {
    @GetMapping(value={"/apply"})
    public String applyPage() {
        return "partner-apply";
    }

    @PostMapping(value={"/testConnection"})
    @ResponseBody
    public String testConnection(@RequestParam String connectionString) {
        try {
            String validatedUrl = SecurityUtil.filterJdbcConnectionSource((String)connectionString);
            DriverManager.getConnection(validatedUrl);
            return "ok:Connection verified, you can proceed with the application";
        }
        catch (Exception e) {
            return "fail:Connection verification failed - " + e.getMessage();
        }
    }

    @PostMapping(value={"/submit"})
    @ResponseBody
    public String submitApply(@RequestParam String company, @RequestParam String contact, @RequestParam String phone, @RequestParam String jdbcUrl) {
        return "Application submitted, we will contact you soon";
    }
}

