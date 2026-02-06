/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.entity.Announcement
 *  com.minioa.mapper.AnnouncementMapper
 *  org.apache.ibatis.annotations.Mapper
 *  org.apache.ibatis.annotations.Param
 */
package com.minioa.mapper;

import com.minioa.entity.Announcement;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface AnnouncementMapper {
    public List<Announcement> findAll();

    public Announcement findById(@Param(value="id") Long var1);

    public int insert(Announcement var1);

    public int deleteById(@Param(value="id") Long var1);
}

