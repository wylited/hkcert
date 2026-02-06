/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.controller.AnnouncementController
 *  com.minioa.entity.Announcement
 *  com.minioa.entity.User
 *  com.minioa.service.AnnouncementService
 *  javax.servlet.http.HttpSession
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.stereotype.Controller
 *  org.springframework.ui.Model
 *  org.springframework.web.bind.annotation.GetMapping
 *  org.springframework.web.bind.annotation.PathVariable
 *  org.springframework.web.bind.annotation.PostMapping
 *  org.springframework.web.bind.annotation.RequestMapping
 *  org.springframework.web.bind.annotation.RequestParam
 */
package com.minioa.controller;

import com.minioa.entity.Announcement;
import com.minioa.entity.User;
import com.minioa.service.AnnouncementService;
import java.util.List;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping(value={"/announcement"})
public class AnnouncementController {
    @Autowired
    private AnnouncementService announcementService;

    @GetMapping(value={"/list"})
    public String list(Model model) {
        List announcements = this.announcementService.findAll();
        model.addAttribute("announcements", (Object)announcements);
        return "announcement-list";
    }

    @GetMapping(value={"/publish"})
    public String publishPage() {
        return "announcement-publish";
    }

    @PostMapping(value={"/publish"})
    public String publishAnnouncement(@RequestParam String title, @RequestParam String content, HttpSession session, Model model) {
        User user = (User)session.getAttribute("user");
        Announcement announcement = new Announcement();
        announcement.setTitle(title);
        announcement.setContent(content);
        announcement.setAuthorId(user.getId());
        boolean success = this.announcementService.publishAnnouncement(announcement);
        if (success) {
            return "redirect:/announcement/list";
        }
        model.addAttribute("error", (Object)"Publish failed");
        return "announcement-publish";
    }

    @GetMapping(value={"/delete/{id}"})
    public String deleteAnnouncement(@PathVariable Long id) {
        this.announcementService.deleteAnnouncement(id);
        return "redirect:/announcement/list";
    }
}

