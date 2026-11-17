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
package io.github.suengineering.eudiw.core.mdoc;

import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A synthetic mdoc issuer for rejection cases the independent fixtures cannot produce: an IACA, a document
 * signer under it, and Documents whose MSO this test code signs. Not a reference: correctness is anchored by the
 * eudi-dev fixtures and the ISO Annex D check.
 */
final class TestMdocIssuer {

    final KeyPair iacaKeys = keys();
    final KeyPair signerKeys = keys();
    final KeyPair deviceKeys = keys();
    final X509Certificate iaca;
    final X509Certificate signer;

    /**
     * @param iacaSubject subject of the IACA, for example {@code "CN=Test IACA,C=DE"}
     * @param signerSubject subject of the document signer
     * @param withEku whether the document signer carries the mDL DS extended key usage
     * @param signerFrom start of the document signer validity
     * @param signerUntil end of the document signer validity
     */
    TestMdocIssuer(String iacaSubject, String signerSubject, boolean withEku, Instant signerFrom, Instant signerUntil)
            throws Exception {
        iaca = certificate(
                iacaSubject,
                iacaSubject,
                iacaKeys,
                iacaKeys,
                true,
                false,
                signerFrom.minusSeconds(86400),
                signerUntil.plusSeconds(86400 * 365));
        signer = certificate(signerSubject, iacaSubject, signerKeys, iacaKeys, false, withEku, signerFrom, signerUntil);
    }

    /**
     * A Document with one namespace of elements, its MSO signed now by the document signer.
     *
     * @param msoNamespace the namespace the MSO holds digests for (may differ from {@code namespace})
     */
    CborItem document(
            String docType,
            String namespace,
            String msoNamespace,
            Map<String, CborItem> elements,
            Instant signed,
            Instant validFrom,
            Instant validUntil)
            throws Exception {
        List<CborItem> items = new ArrayList<>();
        Map<CborItem, CborItem> digests = new LinkedHashMap<>();
        long id = 0;
        for (Map.Entry<String, CborItem> e : elements.entrySet()) {
            byte[] random = new byte[16];
            new SecureRandom().nextBytes(random);
            Map<CborItem, CborItem> item = new LinkedHashMap<>();
            item.put(CborEncoder.text("digestID"), CborEncoder.integer(id));
            item.put(CborEncoder.text("random"), CborEncoder.bytes(random));
            item.put(CborEncoder.text("elementIdentifier"), CborEncoder.text(e.getKey()));
            item.put(CborEncoder.text("elementValue"), e.getValue());
            CborItem bytes = CborEncoder.embedded(CborEncoder.map(item));
            items.add(bytes);
            digests.put(
                    CborEncoder.integer(id),
                    CborEncoder.bytes(MessageDigest.getInstance("SHA-256").digest(bytes.encoded())));
            id++;
        }
        Map<CborItem, CborItem> valueDigests = new LinkedHashMap<>();
        valueDigests.put(CborEncoder.text(msoNamespace), CborEncoder.map(digests));

        Map<CborItem, CborItem> mso = new LinkedHashMap<>();
        mso.put(CborEncoder.text("version"), CborEncoder.text("1.0"));
        mso.put(CborEncoder.text("digestAlgorithm"), CborEncoder.text("SHA-256"));
        mso.put(CborEncoder.text("valueDigests"), CborEncoder.map(valueDigests));
        mso.put(CborEncoder.text("deviceKeyInfo"), CborEncoder.map(Map.of(CborEncoder.text("deviceKey"), deviceKey())));
        mso.put(CborEncoder.text("docType"), CborEncoder.text(docType));
        Map<CborItem, CborItem> validity = new LinkedHashMap<>();
        validity.put(CborEncoder.text("signed"), tdate(signed));
        validity.put(CborEncoder.text("validFrom"), tdate(validFrom));
        validity.put(CborEncoder.text("validUntil"), tdate(validUntil));
        mso.put(CborEncoder.text("validityInfo"), CborEncoder.map(validity));
        byte[] payload = CborEncoder.embedded(CborEncoder.map(mso)).encoded();

        Map<CborItem, CborItem> protectedHeader = new LinkedHashMap<>();
        protectedHeader.put(CborEncoder.integer(1), CborEncoder.integer(-7));
        byte[] protectedBytes = CborEncoder.map(protectedHeader).encoded();
        byte[] toBeSigned = CborEncoder.array(
                        CborEncoder.text("Signature1"),
                        CborEncoder.bytes(protectedBytes),
                        CborEncoder.bytes(new byte[0]),
                        CborEncoder.bytes(payload))
                .encoded();
        Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
        s.initSign(signerKeys.getPrivate());
        s.update(toBeSigned);
        Map<CborItem, CborItem> unprotected = new LinkedHashMap<>();
        unprotected.put(CborEncoder.integer(33), CborEncoder.bytes(signer.getEncoded()));
        CborItem issuerAuth = CborEncoder.array(
                CborEncoder.bytes(protectedBytes),
                CborEncoder.map(unprotected),
                CborEncoder.bytes(payload),
                CborEncoder.bytes(s.sign()));

        Map<CborItem, CborItem> issuerSigned = new LinkedHashMap<>();
        issuerSigned.put(
                CborEncoder.text("nameSpaces"),
                CborEncoder.map(Map.of(CborEncoder.text(namespace), CborEncoder.array(items))));
        issuerSigned.put(CborEncoder.text("issuerAuth"), issuerAuth);
        Map<CborItem, CborItem> document = new LinkedHashMap<>();
        document.put(CborEncoder.text("docType"), CborEncoder.text(docType));
        document.put(CborEncoder.text("issuerSigned"), CborEncoder.map(issuerSigned));
        return CborEncoder.map(document);
    }

    private CborItem deviceKey() {
        ECPublicKey key = (ECPublicKey) deviceKeys.getPublic();
        Map<CborItem, CborItem> k = new LinkedHashMap<>();
        k.put(CborEncoder.integer(1), CborEncoder.integer(2));
        k.put(CborEncoder.integer(-1), CborEncoder.integer(1));
        k.put(CborEncoder.integer(-2), CborEncoder.bytes(fixed(key.getW().getAffineX())));
        k.put(CborEncoder.integer(-3), CborEncoder.bytes(fixed(key.getW().getAffineY())));
        return CborEncoder.map(k);
    }

    private static CborItem tdate(Instant instant) {
        return CborEncoder.tag(0, CborEncoder.text(instant.toString()));
    }

    private static byte[] fixed(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }

    private static KeyPair keys() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate certificate(
            String subject,
            String issuer,
            KeyPair subjectKeys,
            KeyPair issuerKeys,
            boolean ca,
            boolean dsEku,
            Instant from,
            Instant until)
            throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Principal(issuer),
                BigInteger.valueOf(System.nanoTime()),
                Date.from(from),
                Date.from(until),
                new X500Principal(subject),
                subjectKeys.getPublic());
        b.addExtension(Extension.basicConstraints, true, ca ? new BasicConstraints(0) : new BasicConstraints(false));
        b.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (dsEku) {
            b.addExtension(
                    Extension.extendedKeyUsage,
                    true,
                    new ExtendedKeyUsage(
                            KeyPurposeId.getInstance(new ASN1ObjectIdentifier(MdocIssuerVerifier.MDL_DS_EKU))));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
    }
}
