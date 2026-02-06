/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader.archive;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.Manifest;
import org.springframework.boot.loader.archive.Archive;
import org.springframework.boot.loader.jar.JarFile;

public class JarFileArchive
implements Archive {
    private static final String UNPACK_MARKER = "UNPACK:";
    private static final int BUFFER_SIZE = 32768;
    private static final FileAttribute<?>[] NO_FILE_ATTRIBUTES = new FileAttribute[0];
    private static final EnumSet<PosixFilePermission> DIRECTORY_PERMISSIONS = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final EnumSet<PosixFilePermission> FILE_PERMISSIONS = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private final JarFile jarFile;
    private URL url;
    private Path tempUnpackDirectory;

    public JarFileArchive(File file) throws IOException {
        this(file, file.toURI().toURL());
    }

    public JarFileArchive(File file, URL url) throws IOException {
        this(new JarFile(file));
        this.url = url;
    }

    public JarFileArchive(JarFile jarFile) {
        this.jarFile = jarFile;
    }

    @Override
    public URL getUrl() throws MalformedURLException {
        if (this.url != null) {
            return this.url;
        }
        return this.jarFile.getUrl();
    }

    @Override
    public Manifest getManifest() throws IOException {
        return this.jarFile.getManifest();
    }

    @Override
    public Iterator<Archive> getNestedArchives(Archive.EntryFilter searchFilter, Archive.EntryFilter includeFilter) throws IOException {
        return new NestedArchiveIterator(this.jarFile.iterator(), searchFilter, includeFilter);
    }

    @Override
    @Deprecated
    public Iterator<Archive.Entry> iterator() {
        return new EntryIterator(this.jarFile.iterator(), null, null);
    }

    @Override
    public void close() throws IOException {
        this.jarFile.close();
    }

    protected Archive getNestedArchive(Archive.Entry entry) throws IOException {
        JarEntry jarEntry = ((JarFileEntry)entry).getJarEntry();
        if (jarEntry.getComment().startsWith(UNPACK_MARKER)) {
            return this.getUnpackedNestedArchive(jarEntry);
        }
        try {
            JarFile jarFile = this.jarFile.getNestedJarFile(jarEntry);
            return new JarFileArchive(jarFile);
        }
        catch (Exception ex) {
            throw new IllegalStateException("Failed to get nested archive for entry " + entry.getName(), ex);
        }
    }

    private Archive getUnpackedNestedArchive(JarEntry jarEntry) throws IOException {
        Path path;
        String name = jarEntry.getName();
        if (name.lastIndexOf(47) != -1) {
            name = name.substring(name.lastIndexOf(47) + 1);
        }
        if (!Files.exists(path = this.getTempUnpackDirectory().resolve(name), new LinkOption[0]) || Files.size(path) != jarEntry.getSize()) {
            this.unpack(jarEntry, path);
        }
        return new JarFileArchive(path.toFile(), path.toUri().toURL());
    }

    private Path getTempUnpackDirectory() {
        if (this.tempUnpackDirectory == null) {
            Path tempDirectory = Paths.get(System.getProperty("java.io.tmpdir"), new String[0]);
            this.tempUnpackDirectory = this.createUnpackDirectory(tempDirectory);
        }
        return this.tempUnpackDirectory;
    }

    private Path createUnpackDirectory(Path parent) {
        int attempts = 0;
        while (attempts++ < 1000) {
            String fileName = Paths.get(this.jarFile.getName(), new String[0]).getFileName().toString();
            Path unpackDirectory = parent.resolve(fileName + "-spring-boot-libs-" + UUID.randomUUID());
            try {
                this.createDirectory(unpackDirectory);
                return unpackDirectory;
            }
            catch (IOException iOException) {
            }
        }
        throw new IllegalStateException("Failed to create unpack directory in directory '" + parent + "'");
    }

    private void unpack(JarEntry entry, Path path) throws IOException {
        this.createFile(path);
        path.toFile().deleteOnExit();
        try (InputStream inputStream = this.jarFile.getInputStream(entry);
             OutputStream outputStream = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);){
            int bytesRead;
            byte[] buffer = new byte[32768];
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            outputStream.flush();
        }
    }

    private void createDirectory(Path path) throws IOException {
        Files.createDirectory(path, this.getFileAttributes(path.getFileSystem(), DIRECTORY_PERMISSIONS));
    }

    private void createFile(Path path) throws IOException {
        Files.createFile(path, this.getFileAttributes(path.getFileSystem(), FILE_PERMISSIONS));
    }

    private FileAttribute<?>[] getFileAttributes(FileSystem fileSystem, EnumSet<PosixFilePermission> ownerReadWrite) {
        if (!fileSystem.supportedFileAttributeViews().contains("posix")) {
            return NO_FILE_ATTRIBUTES;
        }
        return new FileAttribute[]{PosixFilePermissions.asFileAttribute(ownerReadWrite)};
    }

    public String toString() {
        try {
            return this.getUrl().toString();
        }
        catch (Exception ex) {
            return "jar archive";
        }
    }

    private static class JarFileEntry
    implements Archive.Entry {
        private final JarEntry jarEntry;

        JarFileEntry(JarEntry jarEntry) {
            this.jarEntry = jarEntry;
        }

        JarEntry getJarEntry() {
            return this.jarEntry;
        }

        @Override
        public boolean isDirectory() {
            return this.jarEntry.isDirectory();
        }

        @Override
        public String getName() {
            return this.jarEntry.getName();
        }
    }

    private class NestedArchiveIterator
    extends AbstractIterator<Archive> {
        NestedArchiveIterator(Iterator<JarEntry> iterator, Archive.EntryFilter searchFilter, Archive.EntryFilter includeFilter) {
            super(iterator, searchFilter, includeFilter);
        }

        @Override
        protected Archive adapt(Archive.Entry entry) {
            try {
                return JarFileArchive.this.getNestedArchive(entry);
            }
            catch (IOException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }

    private static class EntryIterator
    extends AbstractIterator<Archive.Entry> {
        EntryIterator(Iterator<JarEntry> iterator, Archive.EntryFilter searchFilter, Archive.EntryFilter includeFilter) {
            super(iterator, searchFilter, includeFilter);
        }

        @Override
        protected Archive.Entry adapt(Archive.Entry entry) {
            return entry;
        }
    }

    private static abstract class AbstractIterator<T>
    implements Iterator<T> {
        private final Iterator<JarEntry> iterator;
        private final Archive.EntryFilter searchFilter;
        private final Archive.EntryFilter includeFilter;
        private Archive.Entry current;

        AbstractIterator(Iterator<JarEntry> iterator, Archive.EntryFilter searchFilter, Archive.EntryFilter includeFilter) {
            this.iterator = iterator;
            this.searchFilter = searchFilter;
            this.includeFilter = includeFilter;
            this.current = this.poll();
        }

        @Override
        public boolean hasNext() {
            return this.current != null;
        }

        @Override
        public T next() {
            T result = this.adapt(this.current);
            this.current = this.poll();
            return result;
        }

        private Archive.Entry poll() {
            while (this.iterator.hasNext()) {
                JarFileEntry candidate = new JarFileEntry(this.iterator.next());
                if (this.searchFilter != null && !this.searchFilter.matches(candidate) || this.includeFilter != null && !this.includeFilter.matches(candidate)) continue;
                return candidate;
            }
            return null;
        }

        protected abstract T adapt(Archive.Entry var1);
    }
}

