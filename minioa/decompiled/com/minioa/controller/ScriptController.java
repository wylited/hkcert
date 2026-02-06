/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.controller.ScriptController
 *  com.minioa.entity.User
 *  com.minioa.service.LuaExecutionService
 *  javax.servlet.http.HttpSession
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.stereotype.Controller
 *  org.springframework.ui.Model
 *  org.springframework.web.bind.annotation.GetMapping
 *  org.springframework.web.bind.annotation.PostMapping
 *  org.springframework.web.bind.annotation.RequestMapping
 *  org.springframework.web.bind.annotation.RequestParam
 *  org.springframework.web.bind.annotation.ResponseBody
 */
package com.minioa.controller;

import com.minioa.entity.User;
import com.minioa.service.LuaExecutionService;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping(value={"/script"})
public class ScriptController {
    @Autowired
    private LuaExecutionService luaExecutionService;

    @GetMapping(value={"/execute"})
    public String executePage(HttpSession session, Model model) {
        User user = (User)session.getAttribute("user");
        if (user == null) {
            return "redirect:/login";
        }
        return "script-execute";
    }

    @PostMapping(value={"/execute"})
    @ResponseBody
    public Map<String, Object> executeScript(@RequestParam String code, HttpSession session) {
        User user = (User)session.getAttribute("user");
        if (user == null) {
            HashMap<String, Object> result = new HashMap<String, Object>();
            result.put("success", false);
            result.put("error", "Not logged in");
            return result;
        }
        return this.luaExecutionService.executeLuaScript(code);
    }
}

