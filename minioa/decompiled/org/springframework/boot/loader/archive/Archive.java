/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader.archive;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Consumer;
import java.util.jar.Manifest;

public interface Archive
extends Iterable<Entry>,
AutoCloseable {
    public URL getUrl() throws MalformedURLException;

    public Manifest getManifest() throws IOException;

    default public Iterator<Archive> getNestedArchives(EntryFilter searchFilter, EntryFilter includeFilter) throws IOException {
        EntryFilter combinedFilter = entry -> !(searchFilter != null && !searchFilter.matches(entry) || includeFilter != null && !includeFilter.matches(entry));
        List<Archive> nestedArchives = this.getNestedArchives(combinedFilter);
        return nestedArchives.iterator();
    }

    @Deprecated
    default public List<Archive> getNestedArchives(EntryFilter filter) throws IOException {
        throw new IllegalStateException("Unexpected call to getNestedArchives(filter)");
    }

    @Override
    @Deprecated
    public Iterator<Entry> iterator();

    @Override
    @Deprecated
    default public void forEach(Consumer<? super Entry> action) {
        Objects.requireNonNull(action);
        for (Entry entry : this) {
            action.accept(entry);
        }
    }

    @Override
    @Deprecated
    default public Spliterator<Entry> spliterator() {
        return Spliterators.spliteratorUnknownSize(this.iterator(), 0);
    }

    default public boolean isExploded() {
        return false;
    }

    @Override
    default public void close() throws Exception {
    }

    @FunctionalInterface
    public static interface EntryFilter {
        public boolean matches(Entry var1);
    }

    public static interface Entry {
        public boolean isDirectory();

        public String getName();
    }
}

