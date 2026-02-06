/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.entity.Asset
 *  com.minioa.mapper.AssetMapper
 *  com.minioa.service.AssetService
 *  org.apache.commons.jxpath.JXPathContext
 *  org.slf4j.Logger
 *  org.slf4j.LoggerFactory
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.stereotype.Service
 */
package com.minioa.service;

import com.minioa.entity.Asset;
import com.minioa.mapper.AssetMapper;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.jxpath.JXPathContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AssetService {
    private static final Logger logger = LoggerFactory.getLogger(AssetService.class);
    @Autowired
    private AssetMapper assetMapper;

    public List<Asset> findAll() {
        return this.assetMapper.findAll();
    }

    public List<Asset> searchByKeyword(String keyword) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return this.findAll();
        }
        return this.assetMapper.searchByKeyword(keyword.trim());
    }

    public List<Asset> searchWithFilter(String keyword, String propertyFilter) {
        List all = this.searchByKeyword(keyword);
        if (propertyFilter == null || propertyFilter.trim().isEmpty()) {
            return all;
        }
        return all.stream().filter(asset -> {
            try {
                JXPathContext context = JXPathContext.newContext((Object)asset);
                Object value = context.getValue(propertyFilter);
                return value != null && (!(value instanceof Boolean) || (Boolean)value != false);
            }
            catch (Exception e) {
                logger.warn("XPath\u7b5b\u9009\u5931\u8d25 - \u8d44\u4ea7ID: {}, \u7b5b\u9009\u8868\u8fbe\u5f0f: {}, \u9519\u8bef: {}", new Object[]{asset.getId(), propertyFilter, e.getMessage()});
                return false;
            }
        }).collect(Collectors.toList());
    }

    public Asset findById(Long id) {
        return this.assetMapper.findById(id);
    }

    public boolean addAsset(Asset asset) {
        return this.assetMapper.insert(asset) > 0;
    }

    public boolean updateAsset(Asset asset) {
        return this.assetMapper.update(asset) > 0;
    }

    public boolean deleteAsset(Long id) {
        return this.assetMapper.deleteById(id) > 0;
    }

    public int batchInsert(List<Asset> assets) {
        int count = 0;
        for (Asset asset : assets) {
            if (this.assetMapper.insert(asset) <= 0) continue;
            ++count;
        }
        return count;
    }
}

