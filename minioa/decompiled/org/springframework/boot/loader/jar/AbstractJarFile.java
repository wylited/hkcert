/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader.jar;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Permission;
import java.util.jar.JarFile;

abstract class AbstractJarFile
extends JarFile {
    AbstractJarFile(File file) throws IOException {
        super(file);
    }

    abstract URL getUrl() throws MalformedURLException;

    abstract JarFileType getType();

    abstract Permission getPermission();

    abstract InputStream getInputStream() throws IOException;

    static enum JarFileType {
        DIRECT,
        NESTED_DIRECTORY,
        NESTED_JAR;

    }
}

