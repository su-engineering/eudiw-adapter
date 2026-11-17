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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import io.github.suengineering.eudiw.core.x509.TestPki;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;

/** Builds synthetic signed trusted lists. Every value is invented; no real list or certificate is used. */
final class TrustedListFixtures {

    static final String EAA_Q = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q";
    static final String CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    static final String GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    static final String WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
    static final String PID_ISSUANCE = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    static final String PID_REVOCATION = "http://uri.etsi.org/19602/SvcType/PID/Revocation";

    record XmlService(String provider, String type, String status, X509Certificate certificate) {}

    record XmlPointer(String location, String territory, String mimeType, X509Certificate signer) {}

    private TrustedListFixtures() {}

    static String xml(
            String type,
            String territory,
            long sequence,
            Instant issued,
            Instant nextUpdate,
            List<XmlPointer> pointers,
            List<XmlService> services) {
        StringBuilder xml = new StringBuilder();
        xml.append(
                "<tsl:TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\""
                        + " xmlns:tslx=\"http://uri.etsi.org/02231/v2/additionaltypes#\" Id=\"tsl\" TSLTag=\"http://uri.etsi.org/19612/TSLTag\">");
        xml.append("<tsl:SchemeInformation><tsl:TSLVersionIdentifier>6</tsl:TSLVersionIdentifier>");
        xml.append("<tsl:TSLSequenceNumber>").append(sequence).append("</tsl:TSLSequenceNumber>");
        xml.append("<tsl:TSLType>").append(type).append("</tsl:TSLType>");
        xml.append(
                "<tsl:SchemeOperatorName><tsl:Name xml:lang=\"en\">Example Operator</tsl:Name></tsl:SchemeOperatorName>");
        xml.append("<tsl:SchemeTerritory>").append(territory).append("</tsl:SchemeTerritory>");
        if (!pointers.isEmpty()) {
            xml.append("<tsl:PointersToOtherTSL>");
            for (XmlPointer pointer : pointers) {
                xml.append(
                                "<tsl:OtherTSLPointer><tsl:ServiceDigitalIdentities><tsl:ServiceDigitalIdentity><tsl:DigitalId>")
                        .append("<tsl:X509Certificate>")
                        .append(b64(pointer.signer()))
                        .append("</tsl:X509Certificate>")
                        .append("</tsl:DigitalId></tsl:ServiceDigitalIdentity></tsl:ServiceDigitalIdentities>")
                        .append("<tsl:TSLLocation>")
                        .append(pointer.location())
                        .append("</tsl:TSLLocation>")
                        .append("<tsl:AdditionalInformation>")
                        .append("<tsl:OtherInformation><tsl:SchemeTerritory>")
                        .append(pointer.territory())
                        .append("</tsl:SchemeTerritory></tsl:OtherInformation>")
                        .append("<tsl:OtherInformation><tslx:MimeType>")
                        .append(pointer.mimeType())
                        .append("</tslx:MimeType></tsl:OtherInformation>")
                        .append("</tsl:AdditionalInformation></tsl:OtherTSLPointer>");
            }
            xml.append("</tsl:PointersToOtherTSL>");
        }
        xml.append("<tsl:ListIssueDateTime>").append(issued).append("</tsl:ListIssueDateTime>");
        xml.append("<tsl:NextUpdate><tsl:dateTime>").append(nextUpdate).append("</tsl:dateTime></tsl:NextUpdate>");
        xml.append("</tsl:SchemeInformation>");
        if (!services.isEmpty()) {
            xml.append("<tsl:TrustServiceProviderList>");
            for (XmlService service : services) {
                xml.append("<tsl:TrustServiceProvider><tsl:TSPInformation><tsl:TSPName><tsl:Name xml:lang=\"en\">")
                        .append(service.provider())
                        .append("</tsl:Name></tsl:TSPName></tsl:TSPInformation><tsl:TSPServices><tsl:TSPService>")
                        .append("<tsl:ServiceInformation><tsl:ServiceTypeIdentifier>")
                        .append(service.type())
                        .append(
                                "</tsl:ServiceTypeIdentifier><tsl:ServiceName><tsl:Name xml:lang=\"en\">Service</tsl:Name></tsl:ServiceName>")
                        .append("<tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>")
                        .append(b64(service.certificate()))
                        .append("</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>")
                        .append("<tsl:ServiceStatus>")
                        .append(service.status())
                        .append("</tsl:ServiceStatus>")
                        .append("<tsl:StatusStartingTime>")
                        .append(issued)
                        .append("</tsl:StatusStartingTime>")
                        .append(
                                "</tsl:ServiceInformation></tsl:TSPService></tsl:TSPServices></tsl:TrustServiceProvider>");
            }
            xml.append("</tsl:TrustServiceProviderList>");
        }
        xml.append("</tsl:TrustServiceStatusList>");
        return xml.toString();
    }

    /** Signs as TS 119 612 Annex B requires: enveloped, exclusive c14n, the list certificate in KeyInfo. */
    static byte[] signXml(String xml, TestPki.Issued signer, String referenceUri) {
        return signXml(xml, signer, referenceUri, DigestMethod.SHA256, SignatureMethod.ECDSA_SHA256);
    }

    static byte[] signXml(
            String xml, TestPki.Issued signer, String referenceUri, String digestMethod, String signatureMethod) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document document =
                    dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            document.getDocumentElement().setIdAttribute("Id", true);
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            List<Transform> transforms = List.of(
                    factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                    factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null));
            Reference reference = factory.newReference(
                    referenceUri, factory.newDigestMethod(digestMethod, null), transforms, null, null);
            SignedInfo signedInfo = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(signatureMethod, null),
                    List.of(reference));
            KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
            KeyInfo keyInfo =
                    keyInfoFactory.newKeyInfo(List.of(keyInfoFactory.newX509Data(List.of(signer.certificate()))));
            DOMSignContext context = new DOMSignContext(signer.keyPair().getPrivate(), document.getDocumentElement());
            context.setDefaultNamespacePrefix("ds");
            factory.newXMLSignature(signedInfo, keyInfo).sign(context);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(out));
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] signXml(String xml, TestPki.Issued signer) {
        return signXml(xml, signer, "");
    }

    /**
     * Signs with the shape published lists have: the list reference plus a second reference to XAdES
     * SignedProperties carried in a {@code ds:Object}.
     */
    static byte[] signXmlXades(String xml, TestPki.Issued signer) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document document =
                    dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            String xades = "http://uri.etsi.org/01903/v1.3.2#";
            org.w3c.dom.Element qualifying = document.createElementNS(xades, "xades:QualifyingProperties");
            qualifying.setAttribute("Target", "#sig");
            org.w3c.dom.Element signed = document.createElementNS(xades, "xades:SignedProperties");
            signed.setAttribute("Id", "xades-sp");
            org.w3c.dom.Element time = document.createElementNS(xades, "xades:SigningTime");
            time.setTextContent("2026-11-01T00:00:00Z");
            org.w3c.dom.Element sigProps = document.createElementNS(xades, "xades:SignedSignatureProperties");
            sigProps.appendChild(time);
            signed.appendChild(sigProps);
            qualifying.appendChild(signed);

            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            Reference list = factory.newReference(
                    "",
                    factory.newDigestMethod(DigestMethod.SHA256, null),
                    List.of(
                            factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                            factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)),
                    null,
                    null);
            Reference properties = factory.newReference(
                    "#xades-sp",
                    factory.newDigestMethod(DigestMethod.SHA256, null),
                    List.of(factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)),
                    "http://uri.etsi.org/01903#SignedProperties",
                    null);
            SignedInfo signedInfo = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(SignatureMethod.ECDSA_SHA256, null),
                    List.of(list, properties));
            KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
            KeyInfo keyInfo =
                    keyInfoFactory.newKeyInfo(List.of(keyInfoFactory.newX509Data(List.of(signer.certificate()))));
            javax.xml.crypto.dsig.XMLObject object =
                    factory.newXMLObject(List.of(new javax.xml.crypto.dom.DOMStructure(qualifying)), null, null, null);
            DOMSignContext context = new DOMSignContext(signer.keyPair().getPrivate(), document.getDocumentElement());
            context.setDefaultNamespacePrefix("ds");
            context.setIdAttributeNS(signed, null, "Id");
            factory.newXMLSignature(signedInfo, keyInfo, List.of(object), "sig", null)
                    .sign(context);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(out));
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A TS 119 602 list in the JSON binding. */
    static Map<String, Object> lote(
            String type, long sequence, Instant issued, Instant nextUpdate, List<Map<String, Object>> entities) {
        Map<String, Object> scheme = new java.util.LinkedHashMap<>();
        scheme.put("LoTEVersionIdentifier", 1);
        scheme.put("LoTESequenceNumber", sequence);
        scheme.put("LoTEType", type);
        scheme.put("SchemeOperatorName", List.of(Map.of("lang", "en", "value", "Example Operator")));
        scheme.put("SchemeTerritory", "EU");
        scheme.put("ListIssueDateTime", issued.toString());
        scheme.put("NextUpdate", nextUpdate.toString());
        Map<String, Object> lote = new java.util.LinkedHashMap<>();
        lote.put("ListAndSchemeInformation", scheme);
        if (!entities.isEmpty()) {
            lote.put("TrustedEntitiesList", entities);
        }
        return Map.of("LoTE", lote);
    }

    static Map<String, Object> entity(String name, String serviceType, X509Certificate certificate) {
        Map<String, Object> information = new java.util.LinkedHashMap<>();
        information.put("ServiceName", List.of(Map.of("lang", "en", "value", "Service")));
        information.put("ServiceTypeIdentifier", serviceType);
        information.put("ServiceDigitalIdentity", Map.of("X509Certificates", List.of(Map.of("val", b64(certificate)))));
        return Map.of(
                "TrustedEntityInformation",
                Map.of(
                        "TEName", List.of(Map.of("lang", "en", "value", name)),
                        "TEAddress", Map.of(),
                        "TEInformationURI", List.of(Map.of("lang", "en", "uriValue", "https://pid.example"))),
                "TrustedEntityServices",
                List.of(Map.of("ServiceInformation", information)));
    }

    /** Compact JAdES B-B: alg, x5c, iat. */
    static byte[] signLote(Map<String, Object> lote, TestPki.Issued signer, Map<String, Object> extraHeader) {
        try {
            List<Base64> x5c = new ArrayList<>();
            x5c.add(Base64.encode(signer.certificate().getEncoded()));
            JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256).x509CertChain(x5c);
            header.customParam("iat", Instant.now().getEpochSecond());
            extraHeader.forEach(header::customParam);
            JWSObject jws = new JWSObject(
                    header.build(), new Payload(io.github.suengineering.eudiw.core.json.Json.toJson(lote)));
            jws.sign(new ECDSASigner((ECPrivateKey) signer.keyPair().getPrivate()));
            return jws.serialize().getBytes(StandardCharsets.US_ASCII);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String b64(X509Certificate certificate) {
        try {
            return java.util.Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
