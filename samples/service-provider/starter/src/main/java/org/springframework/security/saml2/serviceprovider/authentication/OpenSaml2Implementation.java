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

package org.springframework.security.saml2.serviceprovider.authentication;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.security.saml2.Saml2Exception;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.util.Arrays.asList;

final class OpenSaml2Implementation {

	private BasicParserPool parserPool;
	private final AtomicBoolean hasInitCompleted = new AtomicBoolean(false);
	private EncryptedKeyResolver encryptedKeyResolver;

	OpenSaml2Implementation() {
		this(new BasicParserPool());
	}

	OpenSaml2Implementation(BasicParserPool parserPool) {
		this.parserPool = parserPool;
		performInit();
	}

	BasicParserPool getParserPool() {
		return parserPool;
	}

	XMLObject resolve(String xml) {
		return resolve(xml.getBytes(StandardCharsets.UTF_8));
	}

	XMLObject resolve(byte[] xml) {
		XMLObject parsed = parse(xml);
		if (parsed != null) {
			return parsed;
		}
		throw new Saml2Exception("Deserialization not supported for given data set");
	}

	EncryptedKeyResolver getEncryptedKeyResolver() {
		return encryptedKeyResolver;
	}

	/*
	==============================================================
	                     PRIVATE METHODS
	==============================================================
	 */
	private void performInit() {
		if (hasInitCompleted.compareAndSet(false, true)) {
			java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			bootstrap();
		}
	}

	private void bootstrap() {
		//configure default values
		//maxPoolSize = 5;
		getParserPool().setMaxPoolSize(50);
		//coalescing = true;
		getParserPool().setCoalescing(true);
		//expandEntityReferences = false;
		getParserPool().setExpandEntityReferences(false);
		//ignoreComments = true;
		getParserPool().setIgnoreComments(true);
		//ignoreElementContentWhitespace = true;
		getParserPool().setIgnoreElementContentWhitespace(true);
		//namespaceAware = true;
		getParserPool().setNamespaceAware(true);
		//schema = null;
		getParserPool().setSchema(null);
		//dtdValidating = false;
		getParserPool().setDTDValidating(false);
		//xincludeAware = false;
		getParserPool().setXincludeAware(false);

		Map<String, Object> builderAttributes = new HashMap<>();
		getParserPool().setBuilderAttributes(builderAttributes);

		Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
		parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
		parserBuilderFeatures.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
		parserBuilderFeatures.put(
			"http://apache.org/xml/features/validation/schema/normalized-value",
			FALSE
		);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
		parserBuilderFeatures.put("http://apache.org/xml/features/dom/defer-node-expansion", FALSE);
		getParserPool().setBuilderFeatures(parserBuilderFeatures);

		try {
			getParserPool().initialize();
		} catch (ComponentInitializationException x) {
			throw new Saml2Exception("Unable to initialize OpenSaml v3 ParserPool", x);
		}


		try {
			InitializationService.initialize();
		} catch (InitializationException e) {
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

		registry.setParserPool(getParserPool());

		encryptedKeyResolver = new ChainingEncryptedKeyResolver(
			asList(
				new InlineEncryptedKeyResolver(),
				new EncryptedElementTypeEncryptedKeyResolver(),
				new SimpleRetrievalMethodEncryptedKeyResolver()
			)
		);
	}

	private UnmarshallerFactory getUnmarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
	}

	private XMLObject parse(byte[] xml) {
		try {
			Document document = getParserPool().parse(new ByteArrayInputStream(xml));
			Element element = document.getDocumentElement();
			return getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
		} catch (UnmarshallingException | XMLParserException e) {
			throw new Saml2Exception(e);
		}
	}
}
