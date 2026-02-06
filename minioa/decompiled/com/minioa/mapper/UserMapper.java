/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.entity.User
 *  com.minioa.mapper.UserMapper
 *  org.apache.ibatis.annotations.Mapper
 *  org.apache.ibatis.annotations.Param
 */
package com.minioa.mapper;

import com.minioa.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserMapper {
    public User findByUsername(@Param(value="username") String var1);

    public User findById(@Param(value="id") Long var1);

    public int insert(User var1);

    public int update(User var1);

    public int deleteById(@Param(value="id") Long var1);
}

