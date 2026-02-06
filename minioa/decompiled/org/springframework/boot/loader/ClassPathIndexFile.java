/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

final class ClassPathIndexFile {
    private final File root;
    private final List<String> lines;

    private ClassPathIndexFile(File root, List<String> lines) {
        this.root = root;
        this.lines = lines.stream().map(this::extractName).collect(Collectors.toList());
    }

    private String extractName(String line) {
        if (line.startsWith("- \"") && line.endsWith("\"")) {
            return line.substring(3, line.length() - 1);
        }
        throw new IllegalStateException("Malformed classpath index line [" + line + "]");
    }

    int size() {
        return this.lines.size();
    }

    boolean containsEntry(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        return this.lines.contains(name);
    }

    List<URL> getUrls() {
        return Collections.unmodifiableList(this.lines.stream().map(this::asUrl).collect(Collectors.toList()));
    }

    private URL asUrl(String line) {
        try {
            return new File(this.root, line).toURI().toURL();
        }
        catch (MalformedURLException ex) {
            throw new IllegalStateException(ex);
        }
    }

    static ClassPathIndexFile loadIfPossible(URL root, String location) throws IOException {
        return ClassPathIndexFile.loadIfPossible(ClassPathIndexFile.asFile(root), location);
    }

    private static ClassPathIndexFile loadIfPossible(File root, String location) throws IOException {
        return ClassPathIndexFile.loadIfPossible(root, new File(root, location));
    }

    private static ClassPathIndexFile loadIfPossible(File root, File indexFile) throws IOException {
        if (indexFile.exists() && indexFile.isFile()) {
            try (FileInputStream inputStream = new FileInputStream(indexFile);){
                ClassPathIndexFile classPathIndexFile = new ClassPathIndexFile(root, ClassPathIndexFile.loadLines(inputStream));
                return classPathIndexFile;
            }
        }
        return null;
    }

    private static List<String> loadLines(InputStream inputStream) throws IOException {
        ArrayList<String> lines = new ArrayList<String>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        String line = reader.readLine();
        while (line != null) {
            if (!line.trim().isEmpty()) {
                lines.add(line);
            }
            line = reader.readLine();
        }
        return Collections.unmodifiableList(lines);
    }

    private static File asFile(URL url) {
        if (!"file".equals(url.getProtocol())) {
            throw new IllegalArgumentException("URL does not reference a file");
        }
        try {
            return new File(url.toURI());
        }
        catch (URISyntaxException ex) {
            return new File(url.getPath());
        }
    }
}

