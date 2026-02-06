/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.controller.UserController
 *  com.minioa.entity.User
 *  com.minioa.service.UserService
 *  javax.servlet.http.HttpSession
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.stereotype.Controller
 *  org.springframework.ui.Model
 *  org.springframework.web.bind.annotation.GetMapping
 *  org.springframework.web.bind.annotation.PostMapping
 *  org.springframework.web.bind.annotation.RequestMapping
 *  org.springframework.web.bind.annotation.RequestParam
 *  org.springframework.web.multipart.MultipartFile
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequestMapping(value={"/user"})
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping(value={"/profile"})
    public String profile(HttpSession session, Model model) {
        User user = (User)session.getAttribute("user");
        User latestUser = this.userService.findById(user.getId());
        model.addAttribute("user", (Object)latestUser);
        return "profile";
    }

    @PostMapping(value={"/updateProfile"})
    public String updateProfile(@RequestParam String nickname, @RequestParam String bio, HttpSession session, Model model) {
        User user = (User)session.getAttribute("user");
        user.setNickname(nickname);
        user.setBio(bio);
        boolean success = this.userService.updateUser(user);
        if (success) {
            User updatedUser = this.userService.findById(user.getId());
            session.setAttribute("user", (Object)updatedUser);
            model.addAttribute("success", (Object)"Profile updated successfully");
        } else {
            model.addAttribute("error", (Object)"Update failed");
        }
        model.addAttribute("user", (Object)user);
        return "profile";
    }

    @PostMapping(value={"/uploadAvatar"})
    public String uploadAvatar(@RequestParam(value="avatar") MultipartFile file, HttpSession session, Model model) {
        User user;
        try {
            user = (User)session.getAttribute("user");
            String avatarUrl = this.userService.uploadAvatar(file);
            if (avatarUrl != null) {
                user.setAvatarUrl(avatarUrl);
                this.userService.updateUser(user);
                User updatedUser = this.userService.findById(user.getId());
                session.setAttribute("user", (Object)updatedUser);
                model.addAttribute("success", (Object)"Avatar uploaded successfully");
            } else {
                model.addAttribute("error", (Object)"Avatar upload failed");
            }
        }
        catch (Exception e) {
            model.addAttribute("error", (Object)("Avatar upload failed: " + e.getMessage()));
        }
        user = (User)session.getAttribute("user");
        model.addAttribute("user", (Object)user);
        return "profile";
    }
}

