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
import java.nio.charset.StandardCharsets;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.saml2.serviceprovider.provider.Saml2RelyingPartyRegistration;
import org.springframework.security.saml2.serviceprovider.provider.Saml2RelyingPartyRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage.SIGNING;
import static org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2Utils.deflate;
import static org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2Utils.encode;
import static org.springframework.util.Assert.hasText;
import static org.springframework.util.Assert.state;

public class Saml2WebSsoAuthenticationRequestFilter extends OncePerRequestFilter {

	private final AntPathRequestMatcher matcher;
	private final Saml2RelyingPartyRepository providerRepository;
	private Saml2AuthenticationRequestResolver authenticationRequestResolver;
	private final String webSsoUriTemplate;

	public Saml2WebSsoAuthenticationRequestFilter(String filterProcessesUrl,
												  String webSsoUriTemplate,
												  Saml2RelyingPartyRepository providerRepository,
												  Saml2AuthenticationRequestResolver authenticationRequestResolver) {
		hasText(filterProcessesUrl, "filterProcessesUrl must contain an {alias} matcher parameter");
		state(filterProcessesUrl.contains("{alias}"), "filterProcessesUrl must contain an {alias} matcher parameter");
		this.matcher = new AntPathRequestMatcher(filterProcessesUrl);
		this.providerRepository = providerRepository;
		this.authenticationRequestResolver = authenticationRequestResolver;
		this.webSsoUriTemplate = webSsoUriTemplate;
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

		Saml2RelyingPartyRegistration idp = providerRepository.findByAlias(alias);
		String localSpEntityId = Saml2Utils.getServiceProviderEntityId(idp, request);
		Saml2AuthenticationRequest authNRequest = new Saml2AuthenticationRequest(
			localSpEntityId,
			Saml2Utils.resolveUrlTemplate(
				webSsoUriTemplate,
				Saml2Utils.getApplicationUri(request),
				idp.getRemoteIdpEntityId(),
				idp.getAlias()
			),
			idp.getCredentialsForUsage(SIGNING)
		);
		String xml = authenticationRequestResolver.resolveAuthenticationRequest(authNRequest);
		String encoded = encode(deflate(xml));
		String redirect = UriComponentsBuilder
			.fromUri(idp.getIdpWebSsoUrl())
			.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.ISO_8859_1))
			.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.ISO_8859_1))
			.build(true)
			.toUriString();
		response.sendRedirect(redirect);
		if (logger.isDebugEnabled()) {
			logger.debug("SAML2 SP Authentication Request Sent to Browser");
		}

	}

	private String getIdpAlias(HttpServletRequest request) {
		if (matcher.matches(request)) {
			return matcher.extractUriTemplateVariables(request).get("alias");
		}
		return null;

	}

}
