/*
 * Decompiled with CFR 0.152.
 */
package org.springframework.boot.loader.jar;

import java.security.CodeSigner;
import java.security.cert.Certificate;
import java.util.jar.JarEntry;

class JarEntryCertification {
    static final JarEntryCertification NONE = new JarEntryCertification(null, null);
    private final Certificate[] certificates;
    private final CodeSigner[] codeSigners;

    JarEntryCertification(Certificate[] certificates, CodeSigner[] codeSigners) {
        this.certificates = certificates;
        this.codeSigners = codeSigners;
    }

    Certificate[] getCertificates() {
        return this.certificates != null ? (Certificate[])this.certificates.clone() : null;
    }

    CodeSigner[] getCodeSigners() {
        return this.codeSigners != null ? (CodeSigner[])this.codeSigners.clone() : null;
    }

    static JarEntryCertification from(JarEntry certifiedEntry) {
        CodeSigner[] codeSigners;
        Certificate[] certificates = certifiedEntry != null ? certifiedEntry.getCertificates() : null;
        CodeSigner[] codeSignerArray = codeSigners = certifiedEntry != null ? certifiedEntry.getCodeSigners() : null;
        if (certificates == null && codeSigners == null) {
            return NONE;
        }
        return new JarEntryCertification(certificates, codeSigners);
    }
}

