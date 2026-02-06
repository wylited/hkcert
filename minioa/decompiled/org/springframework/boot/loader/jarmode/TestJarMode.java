/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader.jarmode;

import java.util.Arrays;
import org.springframework.boot.loader.jarmode.JarMode;

class TestJarMode
implements JarMode {
    TestJarMode() {
    }

    @Override
    public boolean accepts(String mode) {
        return "test".equals(mode);
    }

    @Override
    public void run(String mode, String[] args) {
        System.out.println("running in " + mode + " jar mode " + Arrays.asList(args));
    }
}

