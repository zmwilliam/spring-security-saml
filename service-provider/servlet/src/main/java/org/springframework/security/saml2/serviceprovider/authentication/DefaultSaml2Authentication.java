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

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;

public class DefaultSaml2Authentication implements Saml2Authentication {
	private boolean authenticated;
	private Object assertion;
	private Object samlResponse;
	private String username;
	private String assertingEntityId;
	private String holdingEntityId;
	private String relayState;
	private String responseXml;

	public DefaultSaml2Authentication(boolean authenticated,
									  String username,
									  Object assertion,
									  Object samlResponse,
									  String assertingEntityId,
									  String holdingEntityId,
									  String relayState,
									  String responseXml) {
		this.authenticated = authenticated;
		this.username = username;
		this.assertion = assertion;
		this.samlResponse = samlResponse;
		this.assertingEntityId = assertingEntityId;
		this.holdingEntityId = holdingEntityId;
		this.relayState = relayState;
		this.responseXml = responseXml;
	}

	@Override
	public String getAssertingEntityId() {
		return assertingEntityId;
	}

	@Override
	public String getHoldingEntityId() {
		return holdingEntityId;
	}

	@Override
	public Object getAssertion() {
		return assertion;
	}

	@Override
	public Object getSamlResponse() {
		return samlResponse;
	}

	@Override
	public String getRelayState() {
		return relayState;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.emptyList();
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getDetails() {
		return getAssertion();
	}

	@Override
	public Object getPrincipal() {
		return getName();
	}

	@Override
	public boolean isAuthenticated() {
		return authenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (!authenticated && isAuthenticated) {
			throw new IllegalArgumentException("Unable to change state of an existing authentication object.");
		}
	}

	@Override
	public String getName() {
		return username;
	}

	public String getResponseXml() {
		return responseXml;
	}
}
