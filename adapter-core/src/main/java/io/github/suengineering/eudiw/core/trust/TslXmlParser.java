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
package io.github.suengineering.eudiw.core.trust;

import io.github.suengineering.eudiw.core.VerificationFailure;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import javax.xml.XMLConstants;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * Verifies and reads an ETSI TS 119 612 V2.4.1 trusted list (XML, namespace {@code http://uri.etsi.org/02231/v2#}),
 * including the EU list of trusted lists.
 *
 * <p>Signature rules (clause 5.7 and Annex B): exactly one {@code ds:Signature}, a direct child of the root;
 * exclusive canonicalization; a reference to the whole list ({@code URI=""} or the root {@code Id}) with exactly the
 * enveloped-signature and exclusive canonicalization transforms; only same-document references; the signing
 * certificate is the one in {@code ds:KeyInfo} and must be one of the allowed signer certificates. Validation runs
 * with the JDK's secure validation mode, and the parser refuses DTDs and external entities.
 */
public final class TslXmlParser {

    /** Maximum accepted size of a list in bytes. */
    public static final int MAX_BYTES = 16 * 1024 * 1024;

    static final String TSL = "http://uri.etsi.org/02231/v2#";
    static final String TSL_ADDITIONAL_TYPES = "http://uri.etsi.org/02231/v2/additionaltypes#";
    private static final String EXCLUSIVE_C14N = CanonicalizationMethod.EXCLUSIVE;

    private TslXmlParser() {}

    /**
     * @param xml the signed list
     * @param location where the list came from; becomes its identifier
     * @param allowedSigners certificates allowed to sign this list
     * @throws VerificationFailure {@code trusted_list_invalid}, {@code trusted_list_signature_invalid} or {@code
     *     trusted_list_signer_untrusted}
     */
    public static TrustedList verify(byte[] xml, String location, Collection<X509Certificate> allowedSigners) {
        if (xml.length > MAX_BYTES) {
            throw new VerificationFailure(ListRules.INVALID, "trusted list too large");
        }
        Document document = parse(xml);
        Element root = document.getDocumentElement();
        if (!TSL.equals(root.getNamespaceURI()) || !"TrustServiceStatusList".equals(root.getLocalName())) {
            throw new VerificationFailure(ListRules.INVALID, "not a TrustServiceStatusList");
        }
        X509Certificate signer = verifySignature(root, allowedSigners);

        Element scheme = child(root, TSL, "SchemeInformation");
        Instant issued = ListRules.instant(text(child(scheme, TSL, "ListIssueDateTime")));
        Element next = child(scheme, TSL, "NextUpdate");
        Optional<Element> nextDate = optionalChild(next, TSL, "dateTime");
        Optional<Instant> nextUpdate = nextDate.map(e -> ListRules.instant(text(e)));
        ListRules.checkDates(issued, nextUpdate);
        ListRules.checkSignerValidity(signer, issued);

        List<TrustedList.Pointer> pointers = new ArrayList<>();
        Optional<Element> pointerList = optionalChild(scheme, TSL, "PointersToOtherTSL");
        if (pointerList.isPresent()) {
            for (Element pointer : children(pointerList.get(), TSL, "OtherTSLPointer")) {
                pointers.add(pointer(pointer));
            }
        }

        List<TrustedList.Service> services = new ArrayList<>();
        Optional<Element> providers = optionalChild(root, TSL, "TrustServiceProviderList");
        if (providers.isPresent()) {
            for (Element provider : children(providers.get(), TSL, "TrustServiceProvider")) {
                String name = name(child(child(provider, TSL, "TSPInformation"), TSL, "TSPName"));
                for (Element service : children(child(provider, TSL, "TSPServices"), TSL, "TSPService")) {
                    Element information = child(service, TSL, "ServiceInformation");
                    services.add(new TrustedList.Service(
                            name,
                            Optional.of(text(child(information, TSL, "ServiceTypeIdentifier"))),
                            Optional.of(text(child(information, TSL, "ServiceStatus"))),
                            certificates(child(information, TSL, "ServiceDigitalIdentity"))));
                }
            }
        }
        return new TrustedList(
                location,
                TrustedList.Format.TSL_XML,
                optionalChild(scheme, TSL, "TSLType").map(TslXmlParser::text),
                optionalChild(scheme, TSL, "SchemeTerritory").map(TslXmlParser::text),
                number(text(child(scheme, TSL, "TSLSequenceNumber"))),
                issued,
                nextUpdate,
                services,
                pointers,
                signer);
    }

    private static Document parse(byte[] xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setErrorHandler(null);
            return builder.parse(new ByteArrayInputStream(xml));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new VerificationFailure(ListRules.INVALID, "trusted list is not well-formed XML", e);
        }
    }

    private static X509Certificate verifySignature(Element root, Collection<X509Certificate> allowedSigners) {
        List<Element> signatures = new ArrayList<>();
        for (Node node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element e
                    && XMLSignature.XMLNS.equals(e.getNamespaceURI())
                    && "Signature".equals(e.getLocalName())) {
                signatures.add(e);
            }
        }
        if (signatures.size() != 1
                || root.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").getLength() != 1) {
            throw new VerificationFailure(
                    ListRules.SIGNATURE_INVALID, "expected exactly one enveloped signature on the list");
        }
        String rootId = root.getAttribute("Id");
        if (!rootId.isEmpty()) {
            root.setIdAttribute("Id", true);
        }
        markXadesIds(root);

        SignerSelector selector = new SignerSelector(allowedSigners);
        DOMValidateContext context = new DOMValidateContext(selector, signatures.get(0));
        context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        try {
            XMLSignature signature = factory.unmarshalXMLSignature(context);
            checkStructure(signature, rootId);
            if (!signature.validate(context)) {
                throw new VerificationFailure(ListRules.SIGNATURE_INVALID, "trusted list signature is invalid");
            }
        } catch (MarshalException | XMLSignatureException e) {
            if (selector.unpinned) {
                throw new VerificationFailure(
                        ListRules.SIGNER_UNTRUSTED, "trusted list signed by an unexpected certificate", e);
            }
            throw new VerificationFailure(ListRules.SIGNATURE_INVALID, "trusted list signature is invalid", e);
        }
        if (selector.signer == null) {
            throw new VerificationFailure(ListRules.SIGNATURE_INVALID, "no signing certificate in KeyInfo");
        }
        if (!allowedSigners.contains(selector.signer)) {
            throw new VerificationFailure(
                    ListRules.SIGNER_UNTRUSTED, "trusted list signed by an unexpected certificate");
        }
        return selector.signer;
    }

    /** XAdES SignedProperties are referenced by an {@code Id} attribute; register those as IDs. */
    private static void markXadesIds(Element root) {
        var all = root.getElementsByTagNameNS("*", "*");
        for (int i = 0; i < all.getLength(); i++) {
            Element element = (Element) all.item(i);
            if ("SignedProperties".equals(element.getLocalName()) && element.hasAttribute("Id")) {
                element.setIdAttribute("Id", true);
            }
        }
    }

    private static void checkStructure(XMLSignature signature, String rootId) {
        if (!EXCLUSIVE_C14N.equals(
                signature.getSignedInfo().getCanonicalizationMethod().getAlgorithm())) {
            throw new VerificationFailure(ListRules.SIGNATURE_INVALID, "canonicalization must be exclusive c14n");
        }
        boolean coversList = false;
        for (Object item : signature.getSignedInfo().getReferences()) {
            Reference reference = (Reference) item;
            String uri = reference.getURI();
            if (uri != null && !uri.isEmpty() && !uri.startsWith("#")) {
                throw new VerificationFailure(ListRules.SIGNATURE_INVALID, "only same-document references are allowed");
            }
            boolean toList = (uri != null && uri.isEmpty()) || (!rootId.isEmpty() && ("#" + rootId).equals(uri));
            if (toList && hasListTransforms(reference)) {
                coversList = true;
            }
        }
        if (!coversList) {
            throw new VerificationFailure(ListRules.SIGNATURE_INVALID, "signature does not cover the whole list");
        }
    }

    private static boolean hasListTransforms(Reference reference) {
        List<?> transforms = reference.getTransforms();
        return transforms.size() == 2
                && Transform.ENVELOPED.equals(((Transform) transforms.get(0)).getAlgorithm())
                && EXCLUSIVE_C14N.equals(((Transform) transforms.get(1)).getAlgorithm());
    }

    /**
     * Takes the signing key from the first X.509 certificate in {@code ds:KeyInfo}, and only if that certificate
     * is an allowed signer, so no signature is computed with an unpinned key.
     */
    private static final class SignerSelector extends KeySelector {
        private final Collection<X509Certificate> allowed;
        private X509Certificate signer;
        private boolean unpinned;

        SignerSelector(Collection<X509Certificate> allowed) {
            this.allowed = allowed;
        }

        @Override
        public KeySelectorResult select(
                KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context)
                throws KeySelectorException {
            if (keyInfo == null || purpose != Purpose.VERIFY || !(method instanceof SignatureMethod)) {
                throw new KeySelectorException("no usable KeyInfo");
            }
            for (Object item : keyInfo.getContent()) {
                if (item instanceof X509Data data) {
                    for (Object content : data.getContent()) {
                        if (content instanceof X509Certificate certificate) {
                            if (!allowed.contains(certificate)) {
                                unpinned = true;
                                throw new KeySelectorException("signing certificate is not an allowed signer");
                            }
                            signer = certificate;
                            Key key = certificate.getPublicKey();
                            return () -> key;
                        }
                    }
                }
            }
            throw new KeySelectorException("no certificate in KeyInfo");
        }
    }

    private static TrustedList.Pointer pointer(Element pointer) {
        String location = text(child(pointer, TSL, "TSLLocation"));
        List<X509Certificate> signers = new ArrayList<>();
        for (Element identity :
                children(child(pointer, TSL, "ServiceDigitalIdentities"), TSL, "ServiceDigitalIdentity")) {
            signers.addAll(certificates(identity));
        }
        Optional<String> type = Optional.empty();
        Optional<String> territory = Optional.empty();
        Optional<String> mimeType = Optional.empty();
        Optional<Element> additional = optionalChild(pointer, TSL, "AdditionalInformation");
        if (additional.isPresent()) {
            for (Element other : children(additional.get(), TSL, "OtherInformation")) {
                for (Node node = other.getFirstChild(); node != null; node = node.getNextSibling()) {
                    if (!(node instanceof Element e)) {
                        continue;
                    }
                    if (TSL.equals(e.getNamespaceURI()) && "TSLType".equals(e.getLocalName())) {
                        type = Optional.of(text(e));
                    } else if (TSL.equals(e.getNamespaceURI()) && "SchemeTerritory".equals(e.getLocalName())) {
                        territory = Optional.of(text(e));
                    } else if (TSL_ADDITIONAL_TYPES.equals(e.getNamespaceURI())
                            && "MimeType".equals(e.getLocalName())) {
                        mimeType = Optional.of(text(e));
                    }
                }
            }
        }
        return new TrustedList.Pointer(location, type, territory, mimeType, signers);
    }

    private static List<X509Certificate> certificates(Element identity) {
        List<X509Certificate> result = new ArrayList<>();
        for (Element digitalId : children(identity, TSL, "DigitalId")) {
            Optional<Element> certificate = optionalChild(digitalId, TSL, "X509Certificate");
            if (certificate.isPresent()) {
                byte[] der;
                try {
                    der = java.util.Base64.getMimeDecoder().decode(text(certificate.get()));
                } catch (IllegalArgumentException e) {
                    throw new VerificationFailure(ListRules.INVALID, "certificate is not base64", e);
                }
                result.add(ListRules.certificate(der));
            }
        }
        return result;
    }

    private static String name(Element names) {
        String first = null;
        for (Element name : children(names, TSL, "Name")) {
            String lang = name.getAttributeNS(XMLConstants.XML_NS_URI, "lang");
            if ("en".equalsIgnoreCase(lang)) {
                return text(name);
            }
            if (first == null) {
                first = text(name);
            }
        }
        if (first == null) {
            throw new VerificationFailure(ListRules.INVALID, "empty name");
        }
        return first;
    }

    private static long number(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new VerificationFailure(ListRules.INVALID, "malformed sequence number", e);
        }
    }

    private static List<Element> children(Element parent, String namespace, String localName) {
        List<Element> result = new ArrayList<>();
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element e
                    && namespace.equals(e.getNamespaceURI())
                    && localName.equals(e.getLocalName())) {
                result.add(e);
            }
        }
        return result;
    }

    private static Optional<Element> optionalChild(Element parent, String namespace, String localName) {
        List<Element> found = children(parent, namespace, localName);
        if (found.size() > 1) {
            throw new VerificationFailure(ListRules.INVALID, "repeated " + localName);
        }
        return found.stream().findFirst();
    }

    private static Element child(Element parent, String namespace, String localName) {
        return optionalChild(parent, namespace, localName)
                .orElseThrow(() -> new VerificationFailure(ListRules.INVALID, "missing " + localName));
    }

    private static String text(Element element) {
        String value = element.getTextContent();
        if (value == null || value.isBlank()) {
            throw new VerificationFailure(ListRules.INVALID, "empty " + element.getLocalName());
        }
        return value.strip();
    }
}
