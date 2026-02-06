/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.entity.Announcement
 *  com.minioa.mapper.AnnouncementMapper
 *  com.minioa.service.AnnouncementService
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.stereotype.Service
 */
package com.minioa.service;

import com.minioa.entity.Announcement;
import com.minioa.mapper.AnnouncementMapper;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AnnouncementService {
    @Autowired
    private AnnouncementMapper announcementMapper;

    public List<Announcement> findAll() {
        return this.announcementMapper.findAll();
    }

    public Announcement findById(Long id) {
        return this.announcementMapper.findById(id);
    }

    public boolean publishAnnouncement(Announcement announcement) {
        return this.announcementMapper.insert(announcement) > 0;
    }

    public boolean deleteAnnouncement(Long id) {
        return this.announcementMapper.deleteById(id) > 0;
    }
}

