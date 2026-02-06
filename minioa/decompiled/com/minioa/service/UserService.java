/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.entity.User
 *  com.minioa.mapper.UserMapper
 *  com.minioa.service.UserService
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.stereotype.Service
 *  org.springframework.web.multipart.MultipartFile
 */
package com.minioa.service;

import com.minioa.entity.User;
import com.minioa.mapper.UserMapper;
import java.io.File;
import java.io.IOException;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public User login(String username, String password) {
        User user = this.userMapper.findByUsername(username);
        if (user != null && user.getPassword().equals(password)) {
            return user;
        }
        return null;
    }

    public boolean register(User user) {
        User existUser = this.userMapper.findByUsername(user.getUsername());
        if (existUser != null) {
            return false;
        }
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("USER");
        }
        return this.userMapper.insert(user) > 0;
    }

    public User findById(Long id) {
        return this.userMapper.findById(id);
    }

    public boolean updateUser(User user) {
        return this.userMapper.update(user) > 0;
    }

    public String uploadAvatar(MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return null;
        }
        String uploadDir = "uploads/avatars/";
        File dir = new File(uploadDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        String originalFilename = file.getOriginalFilename();
        String extension = originalFilename.substring(originalFilename.lastIndexOf("."));
        String filename = UUID.randomUUID().toString() + extension;
        String filepath = uploadDir + filename;
        File dest = new File(filepath);
        file.transferTo(dest);
        return "/avatars/" + filename;
    }
}

