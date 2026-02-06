/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.controller.LoginController
 *  com.minioa.entity.User
 *  com.minioa.service.UserService
 *  javax.servlet.http.HttpSession
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.stereotype.Controller
 *  org.springframework.ui.Model
 *  org.springframework.web.bind.annotation.GetMapping
 *  org.springframework.web.bind.annotation.PostMapping
 *  org.springframework.web.bind.annotation.RequestParam
 */
package com.minioa.controller;

import com.minioa.entity.User;
import com.minioa.service.UserService;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {
    @Autowired
    private UserService userService;

    @GetMapping(value={"/login"})
    public String loginPage() {
        return "login";
    }

    @PostMapping(value={"/doLogin"})
    public String doLogin(@RequestParam String username, @RequestParam String password, HttpSession session, Model model) {
        User user = this.userService.login(username, password);
        if (user != null) {
            session.setAttribute("user", (Object)user);
            return "redirect:/index";
        }
        model.addAttribute("error", (Object)"Invalid username or password");
        return "login";
    }

    @GetMapping(value={"/register"})
    public String registerPage() {
        return "register";
    }

    @PostMapping(value={"/doRegister"})
    public String doRegister(@RequestParam String username, @RequestParam String password, @RequestParam String nickname, Model model) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        user.setNickname(nickname);
        user.setRole("USER");
        boolean success = this.userService.register(user);
        if (success) {
            model.addAttribute("success", (Object)"Registration successful, please login");
            return "login";
        }
        model.addAttribute("error", (Object)"Username already exists");
        return "register";
    }

    @GetMapping(value={"/logout"})
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }
}

