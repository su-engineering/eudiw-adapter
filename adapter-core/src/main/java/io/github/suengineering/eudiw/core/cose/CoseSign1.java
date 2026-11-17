/*
 * Copyright 2026 su-engineering
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.suengineering.eudiw.core.cose;

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.cose.CoseAlgorithm.Curve;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A COSE_Sign1 structure (RFC 9052 section 4.2), verified with an empty external AAD.
 *
 * @param protectedBytes the protected header as received (the content of the byte string)
 * @param protectedHeader the decoded protected header
 * @param unprotectedHeader the unprotected header
 * @param payload the attached payload, or empty when detached
 * @param signature the signature
 */
public record CoseSign1(
        byte[] protectedBytes,
        CborItem.MapItem protectedHeader,
        CborItem.MapItem unprotectedHeader,
        Optional<byte[]> payload,
        byte[] signature) {

    /** COSE header labels (IANA COSE Header Parameters registry). */
    public static final long ALG = 1;

    public static final long CRIT = 2;
    public static final long X5CHAIN = 33;

    private static final long TAG = 18;

    /**
     * Parses a COSE_Sign1, tagged or untagged. The protected header must carry {@code alg}; no label may appear
     * in both headers, and {@code crit} is refused because no critical header is understood.
     *
     * @throws VerificationFailure {@code malformed_credential} for a structure that is not a valid COSE_Sign1
     */
    public static CoseSign1 parse(CborItem item) {
        CborItem body = item instanceof CborItem.Tag t && t.number() == TAG ? t.content() : item;
        if (!(body instanceof CborItem.Array array) || array.items().size() != 4) {
            throw malformed("COSE_Sign1 is not an array of four");
        }
        List<CborItem> parts = array.items();
        if (!(parts.get(0) instanceof CborItem.Bytes protectedBstr)
                || !(parts.get(1) instanceof CborItem.MapItem unprotected)
                || !(parts.get(3) instanceof CborItem.Bytes signature)) {
            throw malformed("COSE_Sign1 has the wrong element types");
        }
        Optional<byte[]> payload =
                switch (parts.get(2)) {
                    case CborItem.Bytes b -> Optional.of(b.value());
                    case CborItem.Simple s when s.isNull() -> Optional.empty();
                    default -> throw malformed("COSE_Sign1 payload is neither bytes nor null");
                };
        byte[] protectedBytes = protectedBstr.value();
        if (protectedBytes.length == 0) {
            throw malformed("COSE_Sign1 protected header is empty");
        }
        if (!(CborDecoder.decode(protectedBytes) instanceof CborItem.MapItem protectedHeader)) {
            throw malformed("COSE_Sign1 protected header is not a map");
        }
        if (protectedHeader.get(ALG).isEmpty()) {
            throw malformed("COSE_Sign1 protected header has no alg");
        }
        if (protectedHeader.get(CRIT).isPresent() || unprotected.get(CRIT).isPresent()) {
            throw malformed("COSE_Sign1 critical headers are not supported");
        }
        for (Map.Entry<CborItem, CborItem> e : unprotected.entries().entrySet()) {
            for (CborItem k : protectedHeader.entries().keySet()) {
                if (CborItem.sameEncoding(k, e.getKey())) {
                    throw malformed("COSE header label in both headers");
                }
            }
        }
        return new CoseSign1(protectedBytes, protectedHeader, unprotected, payload, signature.value());
    }

    /** The {@code alg} value of the protected header. */
    public long algorithm() {
        return protectedHeader
                .get(ALG)
                .filter(CborItem.Int.class::isInstance)
                .flatMap(a -> ((CborItem.Int) a).asLong())
                .orElseThrow(() -> new VerificationFailure("unsupported_algorithm", "COSE alg is not an integer"));
    }

    /**
     * The DER certificates of the {@code x5chain} header, end-entity first (RFC 9360): one byte string or an
     * array of them. Looked up in the unprotected header, where ISO/IEC 18013-5 places it, then the protected.
     */
    public List<byte[]> x5chain() {
        CborItem chain = unprotectedHeader
                .get(X5CHAIN)
                .or(() -> protectedHeader.get(X5CHAIN))
                .orElseThrow(() -> new VerificationFailure("certificate_chain_invalid", "no x5chain"));
        List<byte[]> out = new ArrayList<>();
        switch (chain) {
            case CborItem.Bytes b -> out.add(b.value());
            case CborItem.Array a -> {
                for (CborItem c : a.items()) {
                    if (!(c instanceof CborItem.Bytes b)) {
                        throw new VerificationFailure("certificate_chain_invalid", "x5chain entry is not bytes");
                    }
                    out.add(b.value());
                }
            }
            default -> throw new VerificationFailure("certificate_chain_invalid", "x5chain is neither bytes nor array");
        }
        if (out.isEmpty()) {
            throw new VerificationFailure("certificate_chain_invalid", "x5chain is empty");
        }
        return out;
    }

    /**
     * Verifies the signature over the attached payload.
     *
     * @throws VerificationFailure {@code invalid_signature}, {@code unsupported_algorithm} or {@code
     *     unsupported_key}
     */
    public void verify(PublicKey key) {
        verify(key, payload.orElseThrow(() -> malformed("COSE_Sign1 payload is detached")));
    }

    /** Verifies the signature over a detached payload; an attached payload is refused. */
    public void verifyDetached(PublicKey key, byte[] detachedPayload) {
        if (payload.isPresent()) {
            throw malformed("COSE_Sign1 payload must be detached");
        }
        verify(key, detachedPayload);
    }

    private void verify(PublicKey key, byte[] content) {
        Curve curve = CoseAlgorithm.verifyWith(algorithm(), key);
        byte[] toBeSigned = CborEncoder.array(
                        CborEncoder.text("Signature1"),
                        CborEncoder.bytes(protectedBytes),
                        CborEncoder.bytes(new byte[0]),
                        CborEncoder.bytes(content))
                .encoded();
        int expected = curve == Curve.ED25519 ? 64 : curve == Curve.ED448 ? 114 : 2 * curve.size;
        if (signature.length != expected) {
            throw new VerificationFailure("invalid_signature", "COSE signature has the wrong length");
        }
        try {
            Signature verifier = Signature.getInstance(curve.jcaSignature);
            verifier.initVerify(key);
            verifier.update(toBeSigned);
            if (!verifier.verify(signature)) {
                throw new VerificationFailure("invalid_signature", "COSE signature does not verify");
            }
        } catch (GeneralSecurityException e) {
            throw new VerificationFailure("invalid_signature", "COSE signature cannot be verified", e);
        }
    }

    private static VerificationFailure malformed(String message) {
        return new VerificationFailure("malformed_credential", message);
    }
}
