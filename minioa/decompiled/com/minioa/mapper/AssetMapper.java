/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.entity.Asset
 *  com.minioa.mapper.AssetMapper
 *  org.apache.ibatis.annotations.Mapper
 *  org.apache.ibatis.annotations.Param
 */
package com.minioa.mapper;

import com.minioa.entity.Asset;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface AssetMapper {
    public List<Asset> findAll();

    public List<Asset> searchByKeyword(@Param(value="keyword") String var1);

    public Asset findById(@Param(value="id") Long var1);

    public int insert(Asset var1);

    public int update(Asset var1);

    public int deleteById(@Param(value="id") Long var1);
}

