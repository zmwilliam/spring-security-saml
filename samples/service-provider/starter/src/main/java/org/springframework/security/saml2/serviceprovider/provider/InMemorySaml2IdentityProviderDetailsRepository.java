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

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.util.Assert;

import static java.util.Arrays.asList;
import static org.springframework.util.Assert.notEmpty;
import static org.springframework.util.Assert.notNull;

public class InMemorySaml2IdentityProviderDetailsRepository
		implements Saml2IdentityProviderDetailsRepository, Iterable<Saml2RelyingPartyRegistration> {

	final Map<String, Saml2RelyingPartyRegistration> byId;
	final Map<String, Saml2RelyingPartyRegistration> byAlias;

	public InMemorySaml2IdentityProviderDetailsRepository(Saml2RelyingPartyRegistration... identityProviders) {
		this(asList(identityProviders));
	}

	public InMemorySaml2IdentityProviderDetailsRepository(Collection<Saml2RelyingPartyRegistration> identityProviders) {
		notEmpty(identityProviders, "identity providers cannot be empty");
		byId = createMappingToIdentityProvider(identityProviders, Saml2RelyingPartyRegistration::getRemoteIdpEntityId);
		byAlias = createMappingToIdentityProvider(identityProviders, Saml2RelyingPartyRegistration::getAlias);
	}

	@Override
	public Saml2RelyingPartyRegistration findByEntityId(String entityId) {
		Assert.notNull(entityId, "entityId must not be null");
		return byId.get(entityId);
	}

	@Override
	public Saml2RelyingPartyRegistration findByAlias(String alias) {
		Assert.notNull(alias, "alias must not be null");
		return byAlias.get(alias);
	}

	@Override
	public Iterator<Saml2RelyingPartyRegistration> iterator() {
		return byId.values().iterator();
	}


	private static Map<String, Saml2RelyingPartyRegistration> createMappingToIdentityProvider(
			Collection<Saml2RelyingPartyRegistration> idps,
			Function<Saml2RelyingPartyRegistration,
			String> mapper
	) {
		return Collections.unmodifiableMap(
			idps.stream()
				.peek(idp -> notNull(idp, "identity providers cannot contain null values"))
				.collect(
					Collectors.toMap(
						idp -> mapper.apply(idp),
						Function.identity()
					)
				)
		);
	}

}
