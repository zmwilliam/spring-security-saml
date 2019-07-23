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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage;

import static java.util.Arrays.asList;
import static org.springframework.util.Assert.hasText;
import static org.springframework.util.Assert.notEmpty;
import static org.springframework.util.Assert.notNull;

public class Saml2IdentityProviderDetails {

	private final String entityId;
	private final String alias;
	private final URI webSsoUrl;
	private final List<Saml2X509Credential> credentials;
	private final String localSpEntityId;
	private final String applicationUri;

	protected Saml2IdentityProviderDetails(String idpEntityId,
										   String alias,
										   URI idpWebSsoUri,
										   List<Saml2X509Credential> credentials,
										   String localSpEntityId,
										   String applicationUri) {
		hasText(idpEntityId, "idpEntityId is required");
		hasText(alias, "alias is required");
		hasText(localSpEntityId, "localSpEntityId is required");
		hasText(applicationUri, "applicationUri is required");
		notEmpty(credentials, "credentials are required");
		notNull(idpWebSsoUri, "idpWebSsoUri is required");
		credentials.stream().forEach(c -> notNull(c, "credentials cannot contain null elements"));
		this.entityId = idpEntityId;
		this.alias = alias;
		this.credentials = credentials;
		this.webSsoUrl = idpWebSsoUri;
		this.localSpEntityId = localSpEntityId;
		this.applicationUri = applicationUri;
	}

	public String getEntityId() {
		return entityId;
	}

	public List<Saml2X509Credential> getCredentialsForUsage(Saml2X509CredentialUsage... types) {
		if (types == null || types.length == 0) {
			return credentials;
		}
		Set<Saml2X509CredentialUsage> typeset = new HashSet<>(asList(types));
		return credentials
			.stream()
			.filter(c -> containsCredentialForTypes(c.getSaml2X509CredentialUsages(), typeset))
			.collect(Collectors.toList());
	}

	public String getAlias() {
		return alias;
	}

	public URI getWebSsoUrl() {
		return webSsoUrl;
	}

	public String getLocalSpEntityId() {
		return localSpEntityId;
	}

	public String getApplicationUri() {
		return applicationUri;
	}

	private boolean containsCredentialForTypes(Set<Saml2X509CredentialUsage> existing,
											   Set<Saml2X509CredentialUsage> requested) {
		for (Saml2X509CredentialUsage u : requested) {
			if (existing.contains(u)) {
				return true;
			}
		}
		return false;
	}


}
