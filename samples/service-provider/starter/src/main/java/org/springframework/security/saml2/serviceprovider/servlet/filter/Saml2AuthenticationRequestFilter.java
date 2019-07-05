/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml2.serviceprovider.servlet.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetails;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRegistration;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2EncodingUtils.deflate;
import static org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2EncodingUtils.encode;

public class Saml2AuthenticationRequestFilter extends OncePerRequestFilter {

	private final RequestMatcher matcher;
	private final Saml2ServiceProviderRepository serviceProviderRepository;
	private Saml2AuthenticationRequestResolver authenticationRequestResolver;

	public Saml2AuthenticationRequestFilter(RequestMatcher matcher,
											Saml2ServiceProviderRepository serviceProviderRepository,
											Saml2AuthenticationRequestResolver authenticationRequestResolver) {
		this.matcher = matcher;
		this.serviceProviderRepository = serviceProviderRepository;
		this.authenticationRequestResolver = authenticationRequestResolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			sendAuthenticationRequest(request, response);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	private void sendAuthenticationRequest(HttpServletRequest request,
										   HttpServletResponse response) throws IOException {
		String relayState = request.getParameter("RelayState");
		String alias = getIdpAlias(request);
		if (logger.isDebugEnabled()) {
			logger.debug("Creating SAML2 SP Authentication Request for IDP[" + alias + "]");
		}
		Assert.hasText(alias, "IDP Alias must be present and valid");
		Saml2ServiceProviderRegistration sp = serviceProviderRepository.getServiceProvider(
			ServletUriComponentsBuilder.fromContextPath(request).build().toUriString()
		);
		Saml2IdentityProviderDetails idp = getIdentityProvider(sp, alias);
		String xml = authenticationRequestResolver.resolveAuthenticationRequest(sp, idp);
		String encoded = encode(deflate(xml));
		String redirect = UriComponentsBuilder
			.fromUri(idp.getWebSsoUrl())
			.queryParam("SAMLRequest", encoded)
			.queryParam("RelayState", relayState)
			.build(false)
			.encode()
			.toUriString();
		response.sendRedirect(redirect);
		if (logger.isDebugEnabled()) {
			logger.debug("SAML2 SP Authentication Request Sent to Browser");
		}

	}

	private Saml2IdentityProviderDetails getIdentityProvider(Saml2ServiceProviderRegistration sp, String alias) {
		return serviceProviderRepository.getIdentityProviders(sp.getEntityId()).getIdentityProviderByAlias(alias);
	}


	private String getIdpAlias(HttpServletRequest request) {
		final AntPathRequestMatcher matcher = new AntPathRequestMatcher("/saml/sp/authenticate/{alias}");
		if (matcher.matches(request)) {
			return matcher.extractUriTemplateVariables(request).get("alias");
		}
		return null;

	}

}
