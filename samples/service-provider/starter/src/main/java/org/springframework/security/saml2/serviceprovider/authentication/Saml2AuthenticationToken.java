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

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class Saml2AuthenticationToken extends AbstractAuthenticationToken {
	private final String saml2Response;
	private final String recipientUrl;
	private final String derivedServiceProviderEntityId;

	public Saml2AuthenticationToken(String saml2Response,
									String recipientUrl,
									String derivedServiceProviderEntityId) {
		super(null);
		this.saml2Response = saml2Response;
		this.recipientUrl = recipientUrl;
		this.derivedServiceProviderEntityId = derivedServiceProviderEntityId;
	}

	@Override
	public Object getCredentials() {
		return getSaml2Response();
	}

	@Override
	public Object getPrincipal() {
		return null;
	}

	public String getSaml2Response() {
		return saml2Response;
	}

	public String getRecipientUrl() {
		return recipientUrl;
	}

	public String getDerivedServiceProviderEntityId() {
		return derivedServiceProviderEntityId;
	}

	@Override
	public boolean isAuthenticated() {
		return false;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		throw new IllegalArgumentException();
	}
}
