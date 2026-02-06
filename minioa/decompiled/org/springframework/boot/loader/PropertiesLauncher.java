/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.boot.loader.JarLauncher;
import org.springframework.boot.loader.LaunchedURLClassLoader;
import org.springframework.boot.loader.Launcher;
import org.springframework.boot.loader.archive.Archive;
import org.springframework.boot.loader.archive.ExplodedArchive;
import org.springframework.boot.loader.archive.JarFileArchive;
import org.springframework.boot.loader.util.SystemPropertyUtils;

public class PropertiesLauncher
extends Launcher {
    private static final Class<?>[] PARENT_ONLY_PARAMS = new Class[]{ClassLoader.class};
    private static final Class<?>[] URLS_AND_PARENT_PARAMS = new Class[]{URL[].class, ClassLoader.class};
    private static final Class<?>[] NO_PARAMS = new Class[0];
    private static final URL[] NO_URLS = new URL[0];
    private static final String DEBUG = "loader.debug";
    public static final String MAIN = "loader.main";
    public static final String PATH = "loader.path";
    public static final String HOME = "loader.home";
    public static final String ARGS = "loader.args";
    public static final String CONFIG_NAME = "loader.config.name";
    public static final String CONFIG_LOCATION = "loader.config.location";
    public static final String SET_SYSTEM_PROPERTIES = "loader.system";
    private static final Pattern WORD_SEPARATOR = Pattern.compile("\\W+");
    private static final String NESTED_ARCHIVE_SEPARATOR = "!" + File.separator;
    private final File home;
    private List<String> paths = new ArrayList<String>();
    private final Properties properties = new Properties();
    private final Archive parent;
    private volatile ClassPathArchives classPathArchives;

    public PropertiesLauncher() {
        try {
            this.home = this.getHomeDirectory();
            this.initializeProperties();
            this.initializePaths();
            this.parent = this.createArchive();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    protected File getHomeDirectory() {
        try {
            return new File(this.getPropertyWithDefault(HOME, "${user.dir}"));
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void initializeProperties() throws Exception {
        ArrayList<String> configs = new ArrayList<String>();
        if (this.getProperty(CONFIG_LOCATION) != null) {
            configs.add(this.getProperty(CONFIG_LOCATION));
        } else {
            String[] names;
            for (String name : names = this.getPropertyWithDefault(CONFIG_NAME, "loader").split(",")) {
                configs.add("file:" + this.getHomeDirectory() + "/" + name + ".properties");
                configs.add("classpath:" + name + ".properties");
                configs.add("classpath:BOOT-INF/classes/" + name + ".properties");
            }
        }
        for (String config : configs) {
            InputStream resource = this.getResource(config);
            Throwable throwable = null;
            try {
                if (resource != null) {
                    this.debug("Found: " + config);
                    this.loadResource(resource);
                    return;
                }
                this.debug("Not found: " + config);
            }
            catch (Throwable throwable2) {
                throwable = throwable2;
                throw throwable2;
            }
            finally {
                if (resource == null) continue;
                if (throwable != null) {
                    try {
                        resource.close();
                    }
                    catch (Throwable throwable3) {
                        throwable.addSuppressed(throwable3);
                    }
                    continue;
                }
                resource.close();
            }
        }
    }

    private void loadResource(InputStream resource) throws Exception {
        this.properties.load(resource);
        for (Object key : Collections.list(this.properties.propertyNames())) {
            String text = this.properties.getProperty((String)key);
            String value = SystemPropertyUtils.resolvePlaceholders(this.properties, text);
            if (value == null) continue;
            this.properties.put(key, value);
        }
        if ("true".equals(this.getProperty(SET_SYSTEM_PROPERTIES))) {
            this.debug("Adding resolved properties to System properties");
            for (Object key : Collections.list(this.properties.propertyNames())) {
                String value = this.properties.getProperty((String)key);
                System.setProperty((String)key, value);
            }
        }
    }

    private InputStream getResource(String config) throws Exception {
        if (config.startsWith("classpath:")) {
            return this.getClasspathResource(config.substring("classpath:".length()));
        }
        if (this.isUrl(config = this.handleUrl(config))) {
            return this.getURLResource(config);
        }
        return this.getFileResource(config);
    }

    private String handleUrl(String path) throws UnsupportedEncodingException {
        if ((path.startsWith("jar:file:") || path.startsWith("file:")) && (path = URLDecoder.decode(path, "UTF-8")).startsWith("file:") && (path = path.substring("file:".length())).startsWith("//")) {
            path = path.substring(2);
        }
        return path;
    }

    private boolean isUrl(String config) {
        return config.contains("://");
    }

    private InputStream getClasspathResource(String config) {
        while (config.startsWith("/")) {
            config = config.substring(1);
        }
        config = "/" + config;
        this.debug("Trying classpath: " + config);
        return this.getClass().getResourceAsStream(config);
    }

    private InputStream getFileResource(String config) throws Exception {
        File file = new File(config);
        this.debug("Trying file: " + config);
        if (file.canRead()) {
            return new FileInputStream(file);
        }
        return null;
    }

    private InputStream getURLResource(String config) throws Exception {
        URL url = new URL(config);
        if (this.exists(url)) {
            URLConnection con = url.openConnection();
            try {
                return con.getInputStream();
            }
            catch (IOException ex) {
                if (con instanceof HttpURLConnection) {
                    ((HttpURLConnection)con).disconnect();
                }
                throw ex;
            }
        }
        return null;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private boolean exists(URL url) throws IOException {
        URLConnection connection = url.openConnection();
        try {
            connection.setUseCaches(connection.getClass().getSimpleName().startsWith("JNLP"));
            if (connection instanceof HttpURLConnection) {
                HttpURLConnection httpConnection = (HttpURLConnection)connection;
                httpConnection.setRequestMethod("HEAD");
                int responseCode = httpConnection.getResponseCode();
                if (responseCode == 200) {
                    boolean bl = true;
                    return bl;
                }
                if (responseCode == 404) {
                    boolean bl = false;
                    return bl;
                }
            }
            boolean bl = connection.getContentLength() >= 0;
            return bl;
        }
        finally {
            if (connection instanceof HttpURLConnection) {
                ((HttpURLConnection)connection).disconnect();
            }
        }
    }

    private void initializePaths() throws Exception {
        String path = this.getProperty(PATH);
        if (path != null) {
            this.paths = this.parsePathsProperty(path);
        }
        this.debug("Nested archive paths: " + this.paths);
    }

    private List<String> parsePathsProperty(String commaSeparatedPaths) {
        ArrayList<String> paths = new ArrayList<String>();
        for (String path : commaSeparatedPaths.split(",")) {
            path = (path = this.cleanupPath(path)) == null || path.isEmpty() ? "/" : path;
            paths.add(path);
        }
        if (paths.isEmpty()) {
            paths.add("lib");
        }
        return paths;
    }

    protected String[] getArgs(String ... args) throws Exception {
        String loaderArgs = this.getProperty(ARGS);
        if (loaderArgs != null) {
            String[] defaultArgs = loaderArgs.split("\\s+");
            String[] additionalArgs = args;
            args = new String[defaultArgs.length + additionalArgs.length];
            System.arraycopy(defaultArgs, 0, args, 0, defaultArgs.length);
            System.arraycopy(additionalArgs, 0, args, defaultArgs.length, additionalArgs.length);
        }
        return args;
    }

    @Override
    protected String getMainClass() throws Exception {
        String mainClass = this.getProperty(MAIN, "Start-Class");
        if (mainClass == null) {
            throw new IllegalStateException("No 'loader.main' or 'Start-Class' specified");
        }
        return mainClass;
    }

    @Override
    protected ClassLoader createClassLoader(Iterator<Archive> archives) throws Exception {
        String customLoaderClassName = this.getProperty("loader.classLoader");
        if (customLoaderClassName == null) {
            return super.createClassLoader(archives);
        }
        LinkedHashSet<URL> urls = new LinkedHashSet<URL>();
        while (archives.hasNext()) {
            urls.add(archives.next().getUrl());
        }
        ClassLoader loader = new LaunchedURLClassLoader(urls.toArray(NO_URLS), this.getClass().getClassLoader());
        this.debug("Classpath for custom loader: " + urls);
        loader = this.wrapWithCustomClassLoader(loader, customLoaderClassName);
        this.debug("Using custom class loader: " + customLoaderClassName);
        return loader;
    }

    private ClassLoader wrapWithCustomClassLoader(ClassLoader parent, String className) throws Exception {
        Class<ClassLoader> type = Class.forName(className, true, parent);
        ClassLoader classLoader = this.newClassLoader(type, PARENT_ONLY_PARAMS, parent);
        if (classLoader == null) {
            classLoader = this.newClassLoader(type, URLS_AND_PARENT_PARAMS, NO_URLS, parent);
        }
        if (classLoader == null) {
            classLoader = this.newClassLoader(type, NO_PARAMS, new Object[0]);
        }
        if (classLoader == null) {
            throw new IllegalArgumentException("Unable to create class loader for " + className);
        }
        return classLoader;
    }

    private ClassLoader newClassLoader(Class<ClassLoader> loaderClass, Class<?>[] parameterTypes, Object ... initargs) throws Exception {
        try {
            Constructor<ClassLoader> constructor = loaderClass.getDeclaredConstructor(parameterTypes);
            constructor.setAccessible(true);
            return constructor.newInstance(initargs);
        }
        catch (NoSuchMethodException ex) {
            return null;
        }
    }

    private String getProperty(String propertyKey) throws Exception {
        return this.getProperty(propertyKey, null, null);
    }

    private String getProperty(String propertyKey, String manifestKey) throws Exception {
        return this.getProperty(propertyKey, manifestKey, null);
    }

    private String getPropertyWithDefault(String propertyKey, String defaultValue) throws Exception {
        return this.getProperty(propertyKey, null, defaultValue);
    }

    /*
     * Enabled aggressive block sorting
     * Enabled unnecessary exception pruning
     * Enabled aggressive exception aggregation
     */
    private String getProperty(String propertyKey, String manifestKey, String defaultValue) throws Exception {
        String string;
        String value;
        block22: {
            String property;
            if (manifestKey == null) {
                manifestKey = propertyKey.replace('.', '-');
                manifestKey = PropertiesLauncher.toCamelCase(manifestKey);
            }
            if ((property = SystemPropertyUtils.getProperty(propertyKey)) != null) {
                String value3 = SystemPropertyUtils.resolvePlaceholders(this.properties, property);
                this.debug("Property '" + propertyKey + "' from environment: " + value3);
                return value3;
            }
            if (this.properties.containsKey(propertyKey)) {
                String value4 = SystemPropertyUtils.resolvePlaceholders(this.properties, this.properties.getProperty(propertyKey));
                this.debug("Property '" + propertyKey + "' from properties: " + value4);
                return value4;
            }
            try {
                if (this.home == null) break block22;
                try (ExplodedArchive archive222 = new ExplodedArchive(this.home, false);){
                    String value2;
                    Manifest manifest2 = archive222.getManifest();
                    if (manifest2 != null && (value2 = manifest2.getMainAttributes().getValue(manifestKey)) != null) {
                        this.debug("Property '" + manifestKey + "' from home directory manifest: " + value2);
                        String string2 = SystemPropertyUtils.resolvePlaceholders(this.properties, value2);
                        return string2;
                    }
                }
            }
            catch (IllegalStateException archive222) {
                // empty catch block
            }
        }
        Manifest manifest = this.createArchive().getManifest();
        if (manifest != null && (value = manifest.getMainAttributes().getValue(manifestKey)) != null) {
            this.debug("Property '" + manifestKey + "' from archive manifest: " + value);
            return SystemPropertyUtils.resolvePlaceholders(this.properties, value);
        }
        if (defaultValue != null) {
            string = SystemPropertyUtils.resolvePlaceholders(this.properties, defaultValue);
            return string;
        }
        string = defaultValue;
        return string;
    }

    @Override
    protected Iterator<Archive> getClassPathArchivesIterator() throws Exception {
        ClassPathArchives classPathArchives = this.classPathArchives;
        if (classPathArchives == null) {
            this.classPathArchives = classPathArchives = new ClassPathArchives();
        }
        return classPathArchives.iterator();
    }

    public static void main(String[] args) throws Exception {
        PropertiesLauncher launcher = new PropertiesLauncher();
        args = launcher.getArgs(args);
        launcher.launch(args);
    }

    public static String toCamelCase(CharSequence string) {
        if (string == null) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        Matcher matcher = WORD_SEPARATOR.matcher(string);
        int pos = 0;
        while (matcher.find()) {
            builder.append(PropertiesLauncher.capitalize(string.subSequence(pos, matcher.end()).toString()));
            pos = matcher.end();
        }
        builder.append(PropertiesLauncher.capitalize(string.subSequence(pos, string.length()).toString()));
        return builder.toString();
    }

    private static String capitalize(String str) {
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }

    private void debug(String message) {
        if (Boolean.getBoolean(DEBUG)) {
            System.out.println(message);
        }
    }

    private String cleanupPath(String path) {
        String lowerCasePath;
        if ((path = path.trim()).startsWith("./")) {
            path = path.substring(2);
        }
        if ((lowerCasePath = path.toLowerCase(Locale.ENGLISH)).endsWith(".jar") || lowerCasePath.endsWith(".zip")) {
            return path;
        }
        if (path.endsWith("/*")) {
            path = path.substring(0, path.length() - 1);
        } else if (!path.endsWith("/") && !path.equals(".")) {
            path = path + "/";
        }
        return path;
    }

    void close() throws Exception {
        if (this.classPathArchives != null) {
            this.classPathArchives.close();
        }
        if (this.parent != null) {
            this.parent.close();
        }
    }

    private static final class ArchiveEntryFilter
    implements Archive.EntryFilter {
        private static final String DOT_JAR = ".jar";
        private static final String DOT_ZIP = ".zip";

        private ArchiveEntryFilter() {
        }

        @Override
        public boolean matches(Archive.Entry entry) {
            return entry.getName().endsWith(DOT_JAR) || entry.getName().endsWith(DOT_ZIP);
        }
    }

    private static final class PrefixMatchingArchiveFilter
    implements Archive.EntryFilter {
        private final String prefix;
        private final ArchiveEntryFilter filter = new ArchiveEntryFilter();

        private PrefixMatchingArchiveFilter(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public boolean matches(Archive.Entry entry) {
            if (entry.isDirectory()) {
                return entry.getName().equals(this.prefix);
            }
            return entry.getName().startsWith(this.prefix) && this.filter.matches(entry);
        }
    }

    private class ClassPathArchives
    implements Iterable<Archive> {
        private final List<Archive> classPathArchives;
        private final List<JarFileArchive> jarFileArchives = new ArrayList<JarFileArchive>();

        ClassPathArchives() throws Exception {
            this.classPathArchives = new ArrayList<Archive>();
            for (String path : PropertiesLauncher.this.paths) {
                for (Archive archive : this.getClassPathArchives(path)) {
                    this.addClassPathArchive(archive);
                }
            }
            this.addNestedEntries();
        }

        private void addClassPathArchive(Archive archive) throws IOException {
            if (!(archive instanceof ExplodedArchive)) {
                this.classPathArchives.add(archive);
                return;
            }
            this.classPathArchives.add(archive);
            this.classPathArchives.addAll(this.asList(archive.getNestedArchives(null, new ArchiveEntryFilter())));
        }

        private List<Archive> getClassPathArchives(String path) throws Exception {
            List<Archive> nestedArchives;
            Archive archive;
            String root = PropertiesLauncher.this.cleanupPath(PropertiesLauncher.this.handleUrl(path));
            ArrayList<Archive> lib = new ArrayList<Archive>();
            File file = new File(root);
            if (!"/".equals(root)) {
                if (!this.isAbsolutePath(root)) {
                    file = new File(PropertiesLauncher.this.home, root);
                }
                if (file.isDirectory()) {
                    PropertiesLauncher.this.debug("Adding classpath entries from " + file);
                    archive = new ExplodedArchive(file, false);
                    lib.add(archive);
                }
            }
            if ((archive = this.getArchive(file)) != null) {
                PropertiesLauncher.this.debug("Adding classpath entries from archive " + archive.getUrl() + root);
                lib.add(archive);
            }
            if ((nestedArchives = this.getNestedArchives(root)) != null) {
                PropertiesLauncher.this.debug("Adding classpath entries from nested " + root);
                lib.addAll(nestedArchives);
            }
            return lib;
        }

        private boolean isAbsolutePath(String root) {
            return root.contains(":") || root.startsWith("/");
        }

        private Archive getArchive(File file) throws IOException {
            if (this.isNestedArchivePath(file)) {
                return null;
            }
            String name = file.getName().toLowerCase(Locale.ENGLISH);
            if (name.endsWith(".jar") || name.endsWith(".zip")) {
                return this.getJarFileArchive(file);
            }
            return null;
        }

        private boolean isNestedArchivePath(File file) {
            return file.getPath().contains(NESTED_ARCHIVE_SEPARATOR);
        }

        private List<Archive> getNestedArchives(String path) throws Exception {
            File file;
            Archive parent = PropertiesLauncher.this.parent;
            String root = path;
            if (!root.equals("/") && root.startsWith("/") || parent.getUrl().toURI().equals(PropertiesLauncher.this.home.toURI())) {
                return null;
            }
            int index = root.indexOf(33);
            if (index != -1) {
                file = new File(PropertiesLauncher.this.home, root.substring(0, index));
                if (root.startsWith("jar:file:")) {
                    file = new File(root.substring("jar:file:".length(), index));
                }
                parent = this.getJarFileArchive(file);
                root = root.substring(index + 1);
                while (root.startsWith("/")) {
                    root = root.substring(1);
                }
            }
            if (root.endsWith(".jar") && (file = new File(PropertiesLauncher.this.home, root)).exists()) {
                parent = this.getJarFileArchive(file);
                root = "";
            }
            if (root.equals("/") || root.equals("./") || root.equals(".")) {
                root = "";
            }
            PrefixMatchingArchiveFilter filter = new PrefixMatchingArchiveFilter(root);
            List<Archive> archives = this.asList(parent.getNestedArchives(null, filter));
            if ((root == null || root.isEmpty() || ".".equals(root)) && !path.endsWith(".jar") && parent != PropertiesLauncher.this.parent) {
                archives.add(parent);
            }
            return archives;
        }

        private void addNestedEntries() {
            try {
                Iterator<Archive> archives = PropertiesLauncher.this.parent.getNestedArchives(null, JarLauncher.NESTED_ARCHIVE_ENTRY_FILTER);
                while (archives.hasNext()) {
                    this.classPathArchives.add(archives.next());
                }
            }
            catch (IOException iOException) {
                // empty catch block
            }
        }

        private List<Archive> asList(Iterator<Archive> iterator) {
            ArrayList<Archive> list = new ArrayList<Archive>();
            while (iterator.hasNext()) {
                list.add(iterator.next());
            }
            return list;
        }

        private JarFileArchive getJarFileArchive(File file) throws IOException {
            JarFileArchive archive = new JarFileArchive(file);
            this.jarFileArchives.add(archive);
            return archive;
        }

        @Override
        public Iterator<Archive> iterator() {
            return this.classPathArchives.iterator();
        }

        void close() throws IOException {
            for (JarFileArchive archive : this.jarFileArchives) {
                archive.close();
            }
        }
    }
}

