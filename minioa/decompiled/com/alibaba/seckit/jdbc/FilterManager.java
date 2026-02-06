/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.alibaba.seckit.jdbc.Filter
 *  com.alibaba.seckit.jdbc.FilterManager
 *  com.alibaba.seckit.jdbc.JdbcURLException
 *  com.alibaba.seckit.jdbc.JdbcURLUnsafeException
 *  com.alibaba.seckit.jdbc.filters.DefaultFilter
 */
package com.alibaba.seckit.jdbc;

import com.alibaba.seckit.jdbc.Filter;
import com.alibaba.seckit.jdbc.JdbcURLException;
import com.alibaba.seckit.jdbc.JdbcURLUnsafeException;
import com.alibaba.seckit.jdbc.filters.DefaultFilter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FilterManager {
    private Map<String, Filter> schemaFilterMap = new HashMap();
    private List<Filter> specialCaseFilters = new ArrayList();

    public synchronized void registerFilter(Filter filter) {
        if (filter.getAcceptedSchemes() != null && !filter.getAcceptedSchemes().isEmpty()) {
            for (String scheme : filter.getAcceptedSchemes()) {
                this.schemaFilterMap.put(scheme, filter);
            }
        } else {
            this.specialCaseFilters.add(filter);
        }
    }

    public Filter selectFilter(String url) throws JdbcURLException {
        String scheme;
        if (url == null) {
            throw new JdbcURLUnsafeException("url should not be null");
        }
        for (int i = this.specialCaseFilters.size() - 1; i >= 0; --i) {
            Filter filter = (Filter)this.specialCaseFilters.get(i);
            if (!filter.acceptURL(url)) continue;
            return filter;
        }
        int separator = url.indexOf("//");
        if (separator == -1) {
            int firstColon = url.indexOf(58);
            if (firstColon == -1) {
                throw new JdbcURLUnsafeException("Invalid JDBC URL format: " + url);
            }
            int secondColon = url.indexOf(58, firstColon + 1);
            scheme = secondColon == -1 ? url.substring(0, firstColon + 1).toLowerCase() : url.substring(0, secondColon + 1).toLowerCase();
        } else {
            scheme = url.substring(0, separator).toLowerCase();
        }
        Filter filter = (Filter)this.schemaFilterMap.get(scheme);
        if (filter != null) {
            return filter;
        }
        if (scheme.equalsIgnoreCase("jdbc:mysql:loadbalance:") || scheme.regionMatches(true, 0, "jdbc:oracle:thin:@ldap:", 0, "jdbc:oracle:thin:@ldap:".length()) || url.toLowerCase().contains("h2") && url.toLowerCase().contains("alias")) {
            throw new JdbcURLUnsafeException("detected unsafe database operation: " + scheme);
        }
        return new DefaultFilter();
    }
}

