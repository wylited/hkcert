/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.util.Enumeration;
import java.util.function.Supplier;
import java.util.jar.Manifest;
import org.springframework.boot.loader.archive.Archive;
import org.springframework.boot.loader.jar.Handler;
import org.springframework.boot.loader.jar.JarFile;

public class LaunchedURLClassLoader
extends URLClassLoader {
    private static final int BUFFER_SIZE = 4096;
    private final boolean exploded;
    private final Archive rootArchive;
    private final Object packageLock = new Object();
    private volatile DefinePackageCallType definePackageCallType;

    public LaunchedURLClassLoader(URL[] urls, ClassLoader parent) {
        this(false, urls, parent);
    }

    public LaunchedURLClassLoader(boolean exploded, URL[] urls, ClassLoader parent) {
        this(exploded, null, urls, parent);
    }

    public LaunchedURLClassLoader(boolean exploded, Archive rootArchive, URL[] urls, ClassLoader parent) {
        super(urls, parent);
        this.exploded = exploded;
        this.rootArchive = rootArchive;
    }

    @Override
    public URL findResource(String name) {
        if (this.exploded) {
            return super.findResource(name);
        }
        Handler.setUseFastConnectionExceptions(true);
        try {
            URL uRL = super.findResource(name);
            return uRL;
        }
        finally {
            Handler.setUseFastConnectionExceptions(false);
        }
    }

    @Override
    public Enumeration<URL> findResources(String name) throws IOException {
        if (this.exploded) {
            return super.findResources(name);
        }
        Handler.setUseFastConnectionExceptions(true);
        try {
            UseFastConnectionExceptionsEnumeration useFastConnectionExceptionsEnumeration = new UseFastConnectionExceptionsEnumeration(super.findResources(name));
            return useFastConnectionExceptionsEnumeration;
        }
        finally {
            Handler.setUseFastConnectionExceptions(false);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (name.startsWith("org.springframework.boot.loader.jarmode.")) {
            try {
                Class<?> result = this.loadClassInLaunchedClassLoader(name);
                if (resolve) {
                    this.resolveClass(result);
                }
                return result;
            }
            catch (ClassNotFoundException result) {
                // empty catch block
            }
        }
        if (this.exploded) {
            return super.loadClass(name, resolve);
        }
        Handler.setUseFastConnectionExceptions(true);
        try {
            block10: {
                try {
                    this.definePackageIfNecessary(name);
                }
                catch (IllegalArgumentException ex) {
                    if (this.getPackage(name) != null) break block10;
                    throw new AssertionError((Object)("Package " + name + " has already been defined but it could not be found"));
                }
            }
            Class<?> clazz = super.loadClass(name, resolve);
            return clazz;
        }
        finally {
            Handler.setUseFastConnectionExceptions(false);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private Class<?> loadClassInLaunchedClassLoader(String name) throws ClassNotFoundException {
        Class<?> clazz;
        String internalName = name.replace('.', '/') + ".class";
        InputStream inputStream = this.getParent().getResourceAsStream(internalName);
        if (inputStream == null) {
            throw new ClassNotFoundException(name);
        }
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead = -1;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            inputStream.close();
            byte[] bytes = outputStream.toByteArray();
            Class<?> definedClass = this.defineClass(name, bytes, 0, bytes.length);
            this.definePackageIfNecessary(name);
            clazz = definedClass;
        }
        catch (Throwable throwable) {
            try {
                inputStream.close();
                throw throwable;
            }
            catch (IOException ex) {
                throw new ClassNotFoundException("Cannot load resource for class [" + name + "]", ex);
            }
        }
        inputStream.close();
        return clazz;
    }

    private void definePackageIfNecessary(String className) {
        block3: {
            String packageName;
            int lastDot = className.lastIndexOf(46);
            if (lastDot >= 0 && this.getPackage(packageName = className.substring(0, lastDot)) == null) {
                try {
                    this.definePackage(className, packageName);
                }
                catch (IllegalArgumentException ex) {
                    if (this.getPackage(packageName) != null) break block3;
                    throw new AssertionError((Object)("Package " + packageName + " has already been defined but it could not be found"));
                }
            }
        }
    }

    private void definePackage(String className, String packageName) {
        try {
            AccessController.doPrivileged(() -> {
                String packageEntryName = packageName.replace('.', '/') + "/";
                String classEntryName = className.replace('.', '/') + ".class";
                for (URL url : this.getURLs()) {
                    try {
                        java.util.jar.JarFile jarFile;
                        URLConnection connection = url.openConnection();
                        if (!(connection instanceof JarURLConnection) || (jarFile = ((JarURLConnection)connection).getJarFile()).getEntry(classEntryName) == null || jarFile.getEntry(packageEntryName) == null || jarFile.getManifest() == null) continue;
                        this.definePackage(packageName, jarFile.getManifest(), url);
                        return null;
                    }
                    catch (IOException iOException) {
                        // empty catch block
                    }
                }
                return null;
            }, AccessController.getContext());
        }
        catch (PrivilegedActionException privilegedActionException) {
            // empty catch block
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected Package definePackage(String name, Manifest man, URL url) throws IllegalArgumentException {
        if (!this.exploded) {
            return super.definePackage(name, man, url);
        }
        Object object = this.packageLock;
        synchronized (object) {
            return this.doDefinePackage(DefinePackageCallType.MANIFEST, () -> super.definePackage(name, man, url));
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected Package definePackage(String name, String specTitle, String specVersion, String specVendor, String implTitle, String implVersion, String implVendor, URL sealBase) throws IllegalArgumentException {
        if (!this.exploded) {
            return super.definePackage(name, specTitle, specVersion, specVendor, implTitle, implVersion, implVendor, sealBase);
        }
        Object object = this.packageLock;
        synchronized (object) {
            Manifest manifest;
            if (this.definePackageCallType == null && (manifest = this.getManifest(this.rootArchive)) != null) {
                return this.definePackage(name, manifest, sealBase);
            }
            return this.doDefinePackage(DefinePackageCallType.ATTRIBUTES, () -> super.definePackage(name, specTitle, specVersion, specVendor, implTitle, implVersion, implVendor, sealBase));
        }
    }

    private Manifest getManifest(Archive archive) {
        try {
            return archive != null ? archive.getManifest() : null;
        }
        catch (IOException ex) {
            return null;
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private <T> T doDefinePackage(DefinePackageCallType type, Supplier<T> call) {
        DefinePackageCallType existingType = this.definePackageCallType;
        try {
            this.definePackageCallType = type;
            T t = call.get();
            return t;
        }
        finally {
            this.definePackageCallType = existingType;
        }
    }

    public void clearCache() {
        if (this.exploded) {
            return;
        }
        for (URL url : this.getURLs()) {
            try {
                URLConnection connection = url.openConnection();
                if (!(connection instanceof JarURLConnection)) continue;
                this.clearCache(connection);
            }
            catch (IOException iOException) {
                // empty catch block
            }
        }
    }

    private void clearCache(URLConnection connection) throws IOException {
        java.util.jar.JarFile jarFile = ((JarURLConnection)connection).getJarFile();
        if (jarFile instanceof JarFile) {
            ((JarFile)jarFile).clearCache();
        }
    }

    static {
        ClassLoader.registerAsParallelCapable();
    }

    private static enum DefinePackageCallType {
        MANIFEST,
        ATTRIBUTES;

    }

    private static class UseFastConnectionExceptionsEnumeration
    implements Enumeration<URL> {
        private final Enumeration<URL> delegate;

        UseFastConnectionExceptionsEnumeration(Enumeration<URL> delegate) {
            this.delegate = delegate;
        }

        @Override
        public boolean hasMoreElements() {
            Handler.setUseFastConnectionExceptions(true);
            try {
                boolean bl = this.delegate.hasMoreElements();
                return bl;
            }
            finally {
                Handler.setUseFastConnectionExceptions(false);
            }
        }

        @Override
        public URL nextElement() {
            Handler.setUseFastConnectionExceptions(true);
            try {
                URL uRL = this.delegate.nextElement();
                return uRL;
            }
            finally {
                Handler.setUseFastConnectionExceptions(false);
            }
        }
    }
}

