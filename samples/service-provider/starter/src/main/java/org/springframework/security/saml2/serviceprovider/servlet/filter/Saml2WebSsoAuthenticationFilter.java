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

package org.springframework.security.saml2.serviceprovider.servlet.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetails;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetailsRepository;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2Utils.getApplicationUri;
import static org.springframework.util.Assert.state;
import static org.springframework.util.StringUtils.hasText;

public class Saml2WebSsoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private final AntPathRequestMatcher aliasMatcher;
	private final Saml2IdentityProviderDetailsRepository identityProviderRepository;

	public Saml2WebSsoAuthenticationFilter(String filterProcessesUrl,
										   Saml2IdentityProviderDetailsRepository identityProviderRepository) {
		super(filterProcessesUrl);
		state(filterProcessesUrl.contains("{alias}"), "filterProcessesUrl must contain an {alias} matcher parameter");
		this.identityProviderRepository = identityProviderRepository;
		this.aliasMatcher = new AntPathRequestMatcher(filterProcessesUrl);
		setAllowSessionCreation(true);
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return (super.requiresAuthentication(request, response) && hasText(request.getParameter("SAMLResponse")));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		if (!requiresAuthentication(request, response)) {
			throw new BadCredentialsException("Missing SAML2 response data");
		}
		String saml2Response = request.getParameter("SAMLResponse");
		byte[] b = Saml2EncodingUtils.decode(saml2Response);

		String responseXml = deflateIfRequired(request, b);
		Saml2IdentityProviderDetails idp = identityProviderRepository.getIdentityProviderByAlias(
			getIdpAlias(request),
			getApplicationUri(request)
		);
		final Saml2AuthenticationToken authentication = new Saml2AuthenticationToken(
			responseXml,
			request.getRequestURL().toString(),
			idp
		);
		return getAuthenticationManager().authenticate(authentication);
	}

	private String getIdpAlias(HttpServletRequest request) {
		if (aliasMatcher.matches(request)) {
			return aliasMatcher.extractUriTemplateVariables(request).get("alias");
		}
		return null;
	}

	private String deflateIfRequired(HttpServletRequest request, byte[] b) {
		if (HttpMethod.GET.matches(request.getMethod())) {
			return Saml2EncodingUtils.inflate(b);
		}
		else {
			return new String(b, UTF_8);
		}
	}


}
