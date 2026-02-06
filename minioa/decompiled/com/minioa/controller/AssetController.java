/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.minioa.controller.AssetController
 *  com.minioa.entity.Asset
 *  com.minioa.entity.User
 *  com.minioa.service.AssetService
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

import com.minioa.entity.Asset;
import com.minioa.entity.User;
import com.minioa.service.AssetService;
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
@RequestMapping(value={"/asset"})
public class AssetController {
    @Autowired
    private AssetService assetService;

    @GetMapping(value={"/list"})
    public String list(@RequestParam(required=false) String keyword, @RequestParam(required=false) String propertyFilter, Model model) {
        List assets;
        String filterError = null;
        try {
            assets = this.assetService.searchWithFilter(keyword, propertyFilter);
            if (keyword != null && !keyword.trim().isEmpty()) {
                model.addAttribute("keyword", (Object)keyword);
            }
            if (propertyFilter != null && !propertyFilter.trim().isEmpty()) {
                model.addAttribute("propertyFilter", (Object)propertyFilter);
            }
        }
        catch (Exception e) {
            assets = this.assetService.findAll();
            filterError = "Filter syntax error: " + e.getMessage();
        }
        model.addAttribute("assets", (Object)assets);
        if (filterError != null) {
            model.addAttribute("filterError", (Object)filterError);
        }
        return "asset-list";
    }

    @GetMapping(value={"/add"})
    public String addPage() {
        return "asset-add";
    }

    @PostMapping(value={"/add"})
    public String addAsset(@RequestParam String name, @RequestParam String type, @RequestParam String serialNumber, @RequestParam String description, @RequestParam(required=false) String details, HttpSession session, Model model) {
        User user = (User)session.getAttribute("user");
        Asset asset = new Asset();
        asset.setName(name);
        asset.setType(type);
        asset.setSerialNumber(serialNumber);
        asset.setDescription(description);
        asset.setDetails(details);
        asset.setOwnerId(user.getId());
        boolean success = this.assetService.addAsset(asset);
        if (success) {
            return "redirect:/asset/list";
        }
        model.addAttribute("error", (Object)"Add failed");
        return "asset-add";
    }

    @GetMapping(value={"/delete/{id}"})
    public String deleteAsset(@PathVariable Long id) {
        this.assetService.deleteAsset(id);
        return "redirect:/asset/list";
    }
}

