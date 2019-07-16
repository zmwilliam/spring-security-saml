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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static java.util.Arrays.asList;
import static org.springframework.util.Assert.notEmpty;
import static org.springframework.util.Assert.notNull;

public class InMemorySaml2IdentityProviderDetailsRepository
		implements Saml2IdentityProviderDetailsRepository, Iterable<Saml2IdentityProviderRegistration> {

	private static final char PATH_DELIMITER = '/';
	final Map<String, Saml2IdentityProviderRegistration> byId;
	final Map<String, Saml2IdentityProviderRegistration> byAlias;

	public InMemorySaml2IdentityProviderDetailsRepository(Saml2IdentityProviderRegistration... identityProviders) {
		this(asList(identityProviders));
	}

	public InMemorySaml2IdentityProviderDetailsRepository(Collection<Saml2IdentityProviderRegistration> identityProviders) {
		notEmpty(identityProviders, "identity providers cannot be empty");
		byId = createMappingToIdentityProvider(identityProviders, idp -> idp.getEntityId());
		byAlias = createMappingToIdentityProvider(identityProviders, idp -> idp.getAlias());
	}

	@Override
	public Saml2IdentityProviderDetails getIdentityProviderByEntityId(String entityId, String spRequestUri) {
		Assert.notNull(entityId, "entityId must not be null");
		return withLocalSpEntityId(byId.get(entityId), spRequestUri);
	}

	@Override
	public Saml2IdentityProviderDetails getIdentityProviderByAlias(String alias, String spRequestUri) {
		Assert.notNull(alias, "alias must not be null");
		return withLocalSpEntityId(byAlias.get(alias), spRequestUri);
	}

	@Override
	public Iterator<Saml2IdentityProviderRegistration> iterator() {
		return byId.values().iterator();
	}

	private Saml2IdentityProviderDetails withLocalSpEntityId(Saml2IdentityProviderRegistration idp,
															 String requestUri) {
		String localSpEntityId = inferEntityId(idp.getLocalSpEntityIdTemplate(), requestUri);
		return new Saml2IdentityProviderDetails(
			idp.getEntityId(),
			idp.getAlias(),
			idp.getWebSsoUrl(),
			idp.getCredentials(),
			localSpEntityId
		);
	}

	private static Map<String, Saml2IdentityProviderRegistration> createMappingToIdentityProvider(
			Collection<Saml2IdentityProviderRegistration> idps,
			Function<Saml2IdentityProviderRegistration,
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

	private static String inferEntityId(String template, String url) {
		Map<String, String> uriVariables = new HashMap<>();

		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(url)
			.replaceQuery(null)
			.fragment(null)
			.build();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", scheme == null ? "" : scheme);
		String host = uriComponents.getHost();
		uriVariables.put("baseHost", host == null ? "" : host);
		// following logic is based on HierarchicalUriComponents#toUriString()
		int port = uriComponents.getPort();
		uriVariables.put("basePort", port == -1 ? "" : ":" + port);
		String path = uriComponents.getPath();
		if (StringUtils.hasLength(path)) {
			if (path.charAt(0) != PATH_DELIMITER) {
				path = PATH_DELIMITER + path;
			}
		}
		uriVariables.put("basePath", path == null ? "" : path);
		uriVariables.put("baseUrl", uriComponents.toUriString());

		return UriComponentsBuilder.fromUriString(template)
			.buildAndExpand(uriVariables)
			.toUriString();
	}

}
