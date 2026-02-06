/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.controller.AssetImportController
 *  com.minioa.entity.Asset
 *  com.minioa.entity.User
 *  com.minioa.service.AssetService
 *  javax.servlet.http.HttpSession
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.stereotype.Controller
 *  org.springframework.web.bind.annotation.PostMapping
 *  org.springframework.web.bind.annotation.RequestMapping
 *  org.springframework.web.bind.annotation.RequestParam
 *  org.springframework.web.bind.annotation.ResponseBody
 *  org.springframework.web.multipart.MultipartFile
 *  org.yaml.snakeyaml.Yaml
 *  org.yaml.snakeyaml.constructor.BaseConstructor
 *  org.yaml.snakeyaml.constructor.SafeConstructor
 */
package com.minioa.controller;

import com.minioa.entity.Asset;
import com.minioa.entity.User;
import com.minioa.service.AssetService;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.BaseConstructor;
import org.yaml.snakeyaml.constructor.SafeConstructor;

@Controller
@RequestMapping(value={"/asset"})
public class AssetImportController {
    @Autowired
    private AssetService assetService;

    @PostMapping(value={"/import"})
    @ResponseBody
    public Map<String, Object> importAssets(@RequestParam(value="file") MultipartFile file, HttpSession session) {
        try {
            if (file.isEmpty()) {
                return this.createResponse(false, "File cannot be empty");
            }
            String filename = file.getOriginalFilename();
            if (filename == null || !filename.endsWith(".yaml") && !filename.endsWith(".yml")) {
                return this.createResponse(false, "Only .yaml or .yml format files are supported");
            }
            User user = (User)session.getAttribute("user");
            if (user == null) {
                return this.createResponse(false, "User not logged in");
            }
            Yaml yaml = new Yaml((BaseConstructor)new SafeConstructor());
            InputStream inputStream = file.getInputStream();
            List dataList = (List)yaml.load(inputStream);
            if (dataList == null || dataList.isEmpty()) {
                return this.createResponse(false, "YAML file content is empty");
            }
            ArrayList<Asset> assets = new ArrayList<Asset>();
            for (Map data : dataList) {
                Asset asset = new Asset();
                asset.setName((String)data.get("name"));
                asset.setType((String)data.get("type"));
                asset.setSerialNumber((String)data.get("serialNumber"));
                asset.setDescription((String)data.get("description"));
                asset.setOwnerId(user.getId());
                assets.add(asset);
            }
            int count = this.assetService.batchInsert(assets);
            HashMap<String, Object> response = new HashMap<String, Object>();
            response.put("success", true);
            response.put("message", "Successfully imported " + count + " asset records");
            response.put("count", count);
            return response;
        }
        catch (Exception e) {
            e.printStackTrace();
            return this.createResponse(false, "Import failed: " + e.getMessage());
        }
    }

    private Map<String, Object> createResponse(boolean success, String message) {
        HashMap<String, Object> response = new HashMap<String, Object>();
        response.put("success", success);
        response.put("message", message);
        return response;
    }
}

