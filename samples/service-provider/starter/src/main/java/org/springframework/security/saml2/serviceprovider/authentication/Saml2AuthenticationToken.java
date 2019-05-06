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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;

public class Saml2AuthenticationToken extends AbstractAuthenticationToken {
	private final String saml2Response;
	private final String destinationUrl;
	private final AuthenticatedPrincipal principal;

	public Saml2AuthenticationToken(String saml2Response,
									String destinationUrl) {
		super(null);
		this.saml2Response = saml2Response;
		this.destinationUrl = destinationUrl;
		this.principal = null;
	}

	public Saml2AuthenticationToken(String saml2Response,
									AuthenticatedPrincipal principal,
									Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.saml2Response = saml2Response;
		this.destinationUrl = null;
		this.principal = principal;
		setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return getSaml2Response();
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}

	public String getSaml2Response() {
		return saml2Response;
	}


	public String getDestinationUrl() {
		return destinationUrl;
	}
}
