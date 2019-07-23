/*
 * Copyright 2002-2019 the original author or authors.
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
 *
 */

package org.springframework.security.saml2.serviceprovider;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetails;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.util.Arrays.asList;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage.SIGNING;

public final class OpenSaml2Implementation {
	private static OpenSaml2Implementation instance = new OpenSaml2Implementation();

	private final BasicParserPool parserPool = new BasicParserPool();

	private final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
			asList(
				new InlineEncryptedKeyResolver(),
				new EncryptedElementTypeEncryptedKeyResolver(),
				new SimpleRetrievalMethodEncryptedKeyResolver()
			)
	);

	private OpenSaml2Implementation() {
		bootstrap();
	}
	/*
	 * ==============================================================
	 * PUBLIC METHODS
	 * ==============================================================
	 */
	public static OpenSaml2Implementation getInstance() {
		return instance;
	}

	public <T> T buildSAMLObject(final Class<T> clazz) {
		try {
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			return (T) getBuilderFactory().getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException e) {
			throw new Saml2Exception("Could not create SAML object", e);
		} catch (NoSuchFieldException e) {
			throw new Saml2Exception("Could not create SAML object", e);
		}
	}

	public XMLObject resolve(String xml) {
		return resolve(xml.getBytes(StandardCharsets.UTF_8));
	}

	public EncryptedKeyResolver getEncryptedKeyResolver() {
		return encryptedKeyResolver;
	}

	public String toXml(XMLObject object, Saml2IdentityProviderDetails idp)
		throws MarshallingException, SignatureException, SecurityException {
		if (object instanceof SignableSAMLObject && hasSigningCredential(idp)) {
			signXmlObject((SignableSAMLObject) object, idp);
		}
		final MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		Element element = marshallerFactory.getMarshaller(object).marshall(object);
		return SerializeSupport.nodeToString(element);
	}

	public KeyDescriptor getKeyDescriptor(Saml2X509Credential credential, Saml2X509CredentialUsage usage) {
		KeyDescriptor result = buildSAMLObject(KeyDescriptor.class);
		final BasicCredential bc = getBasicCredential(credential);
		KeyInfo keyInfo = null;
		try {
			keyInfo = DefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager()
				.getDefaultManager()
				.getFactory(bc)
				.newInstance()
				.generate(bc);
		}
		catch (SecurityException e) {
			throw new IllegalArgumentException(e);
		}
		result.setKeyInfo(keyInfo);
		switch (usage) {
			case SIGNING:
				result.setUse(UsageType.SIGNING);
				break;
			case DECRYPTION:
			case ENCRYPTION:
				result.setUse(UsageType.ENCRYPTION);
				break;
			default: //noop
		}

		return result;
	}


	/*
	 * ==============================================================
	 * PRIVATE METHODS
	 * ==============================================================
	 */
	private void bootstrap() {
		// configure default values
		// maxPoolSize = 5;
		parserPool.setMaxPoolSize(50);
		// coalescing = true;
		parserPool.setCoalescing(true);
		// expandEntityReferences = false;
		parserPool.setExpandEntityReferences(false);
		// ignoreComments = true;
		parserPool.setIgnoreComments(true);
		// ignoreElementContentWhitespace = true;
		parserPool.setIgnoreElementContentWhitespace(true);
		// namespaceAware = true;
		parserPool.setNamespaceAware(true);
		// schema = null;
		parserPool.setSchema(null);
		// dtdValidating = false;
		parserPool.setDTDValidating(false);
		// xincludeAware = false;
		parserPool.setXincludeAware(false);

		Map<String, Object> builderAttributes = new HashMap<>();
		parserPool.setBuilderAttributes(builderAttributes);

		Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
		parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
		parserBuilderFeatures.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
		parserBuilderFeatures.put("http://apache.org/xml/features/validation/schema/normalized-value", FALSE);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
		parserBuilderFeatures.put("http://apache.org/xml/features/dom/defer-node-expansion", FALSE);
		parserPool.setBuilderFeatures(parserBuilderFeatures);

		try {
			parserPool.initialize();
		}
		catch (ComponentInitializationException x) {
			throw new Saml2Exception("Unable to initialize OpenSaml v3 ParserPool", x);
		}

		try {
			InitializationService.initialize();
		}
		catch (InitializationException e) {
			throw new Saml2Exception("Unable to initialize OpenSaml v3", e);
		}

		XMLObjectProviderRegistry registry;
		synchronized (ConfigurationService.class) {
			registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			if (registry == null) {
				registry = new XMLObjectProviderRegistry();
				ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
			}
		}

		registry.setParserPool(parserPool);
	}

	private boolean hasSigningCredential(Saml2IdentityProviderDetails idp) {
		return !idp.getCredentialsForUsage(SIGNING).isEmpty();
	}

	private XMLObject resolve(byte[] xml) {
		XMLObject parsed = parse(xml);
		if (parsed != null) {
			return parsed;
		}
		throw new Saml2Exception("Deserialization not supported for given data set");
	}

	private UnmarshallerFactory getUnmarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
	}

	private XMLObject parse(byte[] xml) {
		try {
			Document document = parserPool.parse(new ByteArrayInputStream(xml));
			Element element = document.getDocumentElement();
			return getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
		}
		catch (UnmarshallingException | XMLParserException e) {
			throw new Saml2Exception(e);
		}
	}

	private Credential getSigningCredential(Saml2IdentityProviderDetails idp) {
		Saml2X509Credential credential = idp.getCredentialsForUsage(SIGNING)
			.stream()
			.findFirst()
			.orElseThrow(() -> new IllegalArgumentException("no signing credential configured"));
		BasicCredential cred = getBasicCredential(credential);
		cred.setEntityId(idp.getLocalSpEntityId());
		cred.setUsageType(UsageType.SIGNING);
		return cred;
	}

	private BasicCredential getBasicCredential(Saml2X509Credential credential) {
		PublicKey publicKey = credential.getCertificate().getPublicKey();
		final PrivateKey privateKey = credential.getPrivateKey();
		return CredentialSupport.getSimpleCredential(publicKey, privateKey);
	}

	private void signXmlObject(SignableSAMLObject object, Saml2IdentityProviderDetails idp)
		throws MarshallingException, SecurityException, SignatureException {
		Credential credential = getSigningCredential(idp);
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		parameters.setSigningCredential(credential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		SignatureSupport.signObject(object, parameters);
	}

}
