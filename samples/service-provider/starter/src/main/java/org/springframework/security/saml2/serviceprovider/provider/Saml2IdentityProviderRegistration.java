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

package org.springframework.security.saml2.serviceprovider.provider;

import java.net.URI;
import java.util.List;

import org.springframework.security.saml2.credentials.Saml2X509Credential;

import static java.util.Optional.ofNullable;

/**
 * Configuration object that represents an external identity provider paired with the local service provider
 */
public class Saml2IdentityProviderRegistration {

	private String entityId;
	private String alias;
	private URI webSsoUrl;
	private List<Saml2X509Credential> credentials;
	private String localSpEntityIdTemplate = "{baseUrl}";

	public Saml2IdentityProviderRegistration() {
	}

	public Saml2IdentityProviderRegistration(String idpEntityId,
											 String alias,
											 URI idpWebSsoUri,
											 List<Saml2X509Credential> credentials,
											 String localSpEntityIdTemplate) {
		this.entityId = idpEntityId;
		this.alias = alias;
		this.credentials = credentials;
		this.webSsoUrl = idpWebSsoUri;
		this.localSpEntityIdTemplate = ofNullable(localSpEntityIdTemplate).orElse("{baseUrl}");
	}

	public String getEntityId() {
		return entityId;
	}

	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public URI getWebSsoUrl() {
		return webSsoUrl;
	}

	public void setWebSsoUrl(URI webSsoUrl) {
		this.webSsoUrl = webSsoUrl;
	}

	public List<Saml2X509Credential> getCredentials() {
		return credentials;
	}

	public void setCredentials(List<Saml2X509Credential> credentials) {
		this.credentials = credentials;
	}

	public String getLocalSpEntityIdTemplate() {
		return localSpEntityIdTemplate;
	}

	public void setLocalSpEntityIdTemplate(String localSpEntityIdTemplate) {
		this.localSpEntityIdTemplate = localSpEntityIdTemplate;
	}
}
