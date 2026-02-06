/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  com.fasterxml.jackson.databind.ObjectMapper
 *  com.minioa.service.LuaExecutionService
 *  org.springframework.stereotype.Service
 */
package com.minioa.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class LuaExecutionService {
    public Map<String, Object> executeLuaScript(String string) {
        Object object;
        if (string != null && (((String)(object = string.toLowerCase())).contains("custom_args") || ((String)object).contains("file://") || ((String)object).contains("file:"))) {
            HashMap<String, Object> hashMap = new HashMap<String, Object>();
            hashMap.put("success", false);
            hashMap.put("error", "");
            hashMap.put("output", "");
            return hashMap;
        }
        object = new HashMap();
        HashMap<String, String> hashMap = new HashMap<String, String>();
        hashMap.put("code", string);
        try {
            Object object2;
            ObjectMapper objectMapper = new ObjectMapper();
            String string2 = objectMapper.writeValueAsString(hashMap);
            URL uRL = new URL("http://localhost:8080/execute");
            HttpURLConnection httpURLConnection = (HttpURLConnection)uRL.openConnection();
            httpURLConnection.setRequestMethod("POST");
            httpURLConnection.setRequestProperty("Content-Type", "application/json");
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setConnectTimeout(10000);
            httpURLConnection.setReadTimeout(10000);
            Object object3 = httpURLConnection.getOutputStream();
            Object object4 = null;
            try {
                object2 = string2.getBytes(StandardCharsets.UTF_8);
                ((OutputStream)object3).write((byte[])object2, 0, ((byte[])object2).length);
            }
            catch (Throwable throwable) {
                object4 = throwable;
                throw throwable;
            }
            finally {
                if (object3 != null) {
                    if (object4 != null) {
                        try {
                            ((OutputStream)object3).close();
                        }
                        catch (Throwable throwable) {
                            ((Throwable)object4).addSuppressed(throwable);
                        }
                    } else {
                        ((OutputStream)object3).close();
                    }
                }
            }
            object3 = new StringBuilder();
            object4 = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream(), StandardCharsets.UTF_8));
            object2 = null;
            try {
                String string3;
                while ((string3 = ((BufferedReader)object4).readLine()) != null) {
                    ((StringBuilder)object3).append(string3.trim());
                }
            }
            catch (Throwable throwable) {
                object2 = throwable;
                throw throwable;
            }
            finally {
                if (object4 != null) {
                    if (object2 != null) {
                        try {
                            ((BufferedReader)object4).close();
                        }
                        catch (Throwable throwable) {
                            ((Throwable)object2).addSuppressed(throwable);
                        }
                    } else {
                        ((BufferedReader)object4).close();
                    }
                }
            }
            object4 = (Map)objectMapper.readValue(((StringBuilder)object3).toString(), Map.class);
            ((HashMap)object).put("success", true);
            ((HashMap)object).put("output", object4.get("output"));
            ((HashMap)object).put("error", object4.get("error"));
        }
        catch (Exception exception) {
            ((HashMap)object).put("success", false);
            ((HashMap)object).put("error", "Execution failed: " + exception.getMessage());
            ((HashMap)object).put("output", "");
        }
        return object;
    }
}

