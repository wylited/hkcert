/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import org.springframework.boot.loader.ClassPathIndexFile;
import org.springframework.boot.loader.Launcher;
import org.springframework.boot.loader.archive.Archive;
import org.springframework.boot.loader.archive.ExplodedArchive;

public abstract class ExecutableArchiveLauncher
extends Launcher {
    private static final String START_CLASS_ATTRIBUTE = "Start-Class";
    protected static final String BOOT_CLASSPATH_INDEX_ATTRIBUTE = "Spring-Boot-Classpath-Index";
    protected static final String DEFAULT_CLASSPATH_INDEX_FILE_NAME = "classpath.idx";
    private final Archive archive;
    private final ClassPathIndexFile classPathIndex;

    public ExecutableArchiveLauncher() {
        try {
            this.archive = this.createArchive();
            this.classPathIndex = this.getClassPathIndex(this.archive);
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    protected ExecutableArchiveLauncher(Archive archive) {
        try {
            this.archive = archive;
            this.classPathIndex = this.getClassPathIndex(this.archive);
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    protected ClassPathIndexFile getClassPathIndex(Archive archive) throws IOException {
        if (archive instanceof ExplodedArchive) {
            String location = this.getClassPathIndexFileLocation(archive);
            return ClassPathIndexFile.loadIfPossible(archive.getUrl(), location);
        }
        return null;
    }

    private String getClassPathIndexFileLocation(Archive archive) throws IOException {
        Manifest manifest = archive.getManifest();
        Attributes attributes = manifest != null ? manifest.getMainAttributes() : null;
        String location = attributes != null ? attributes.getValue(BOOT_CLASSPATH_INDEX_ATTRIBUTE) : null;
        return location != null ? location : this.getArchiveEntryPathPrefix() + DEFAULT_CLASSPATH_INDEX_FILE_NAME;
    }

    @Override
    protected String getMainClass() throws Exception {
        Manifest manifest = this.archive.getManifest();
        String mainClass = null;
        if (manifest != null) {
            mainClass = manifest.getMainAttributes().getValue(START_CLASS_ATTRIBUTE);
        }
        if (mainClass == null) {
            throw new IllegalStateException("No 'Start-Class' manifest entry specified in " + this);
        }
        return mainClass;
    }

    @Override
    protected ClassLoader createClassLoader(Iterator<Archive> archives) throws Exception {
        ArrayList<URL> urls = new ArrayList<URL>(this.guessClassPathSize());
        while (archives.hasNext()) {
            urls.add(archives.next().getUrl());
        }
        if (this.classPathIndex != null) {
            urls.addAll(this.classPathIndex.getUrls());
        }
        return this.createClassLoader(urls.toArray(new URL[0]));
    }

    private int guessClassPathSize() {
        if (this.classPathIndex != null) {
            return this.classPathIndex.size() + 10;
        }
        return 50;
    }

    @Override
    protected Iterator<Archive> getClassPathArchivesIterator() throws Exception {
        Archive.EntryFilter searchFilter = this::isSearchCandidate;
        Iterator<Archive> archives = this.archive.getNestedArchives(searchFilter, entry -> this.isNestedArchive(entry) && !this.isEntryIndexed(entry));
        if (this.isPostProcessingClassPathArchives()) {
            archives = this.applyClassPathArchivePostProcessing(archives);
        }
        return archives;
    }

    private boolean isEntryIndexed(Archive.Entry entry) {
        if (this.classPathIndex != null) {
            return this.classPathIndex.containsEntry(entry.getName());
        }
        return false;
    }

    private Iterator<Archive> applyClassPathArchivePostProcessing(Iterator<Archive> archives) throws Exception {
        ArrayList<Archive> list = new ArrayList<Archive>();
        while (archives.hasNext()) {
            list.add(archives.next());
        }
        this.postProcessClassPathArchives(list);
        return list.iterator();
    }

    protected boolean isSearchCandidate(Archive.Entry entry) {
        if (this.getArchiveEntryPathPrefix() == null) {
            return true;
        }
        return entry.getName().startsWith(this.getArchiveEntryPathPrefix());
    }

    protected abstract boolean isNestedArchive(Archive.Entry var1);

    protected boolean isPostProcessingClassPathArchives() {
        return true;
    }

    protected void postProcessClassPathArchives(List<Archive> archives) throws Exception {
    }

    protected String getArchiveEntryPathPrefix() {
        return null;
    }

    @Override
    protected boolean isExploded() {
        return this.archive.isExploded();
    }

    @Override
    protected final Archive getArchive() {
        return this.archive;
    }
}

