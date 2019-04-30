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

package org.springframework.security.saml2.spi;

import java.io.ByteArrayInputStream;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.datatype.Duration;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.util.Saml2KeyData;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.DOMTypeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

public final class OpenSaml2Implementation extends Saml2JavaAbstraction<OpenSaml2Implementation> {

	private BasicParserPool parserPool;

	public OpenSaml2Implementation() {
		this(Clock.systemUTC());
	}

	public OpenSaml2Implementation(Clock time) {
		this(time, new BasicParserPool());
	}

	public OpenSaml2Implementation(Clock time, BasicParserPool parserPool) {
		super(time);
		this.parserPool = parserPool;
	}

	protected BasicParserPool getParserPool() {
		return parserPool;
	}

	private UnmarshallerFactory getUnmarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
	}

	@Override
	protected void bootstrap() {
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
	}

	@Override
	protected Duration toDuration(long millis) {
		if (millis < 0) {
			return null;
		}
		else {
			return DOMTypeSupport.getDataTypeFactory().newDuration(millis);
		}
	}

	@Override
	public Object resolve(byte[] xml, List<Saml2KeyData> localKeys) {
		XMLObject parsed = parse(xml);
		if (parsed != null) {
			return parsed;
		}
		throw new Saml2Exception("Deserialization not yet supported.");
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
