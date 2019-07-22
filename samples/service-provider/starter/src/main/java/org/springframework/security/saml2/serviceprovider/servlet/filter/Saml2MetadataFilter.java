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

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.saml2.serviceprovider.metadata.Saml2ServiceProviderMetadataResolver;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetails;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetailsRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2Utils.getApplicationUri;
import static org.springframework.util.Assert.hasText;
import static org.springframework.util.Assert.state;

public class Saml2MetadataFilter extends OncePerRequestFilter {

	private final AntPathRequestMatcher matcher;
	private final Saml2IdentityProviderDetailsRepository providerRepository;
	private Saml2ServiceProviderMetadataResolver metadataResolver;

	public Saml2MetadataFilter(String filterProcessesUrl,
							   Saml2IdentityProviderDetailsRepository providerRepository,
							   Saml2ServiceProviderMetadataResolver metadataResolver) {
		hasText(filterProcessesUrl, "filterProcessesUrl must contain an {alias} matcher parameter");
		state(filterProcessesUrl.contains("{alias}"), "filterProcessesUrl must contain an {alias} matcher parameter");
		this.matcher = new AntPathRequestMatcher(filterProcessesUrl);
		this.providerRepository = providerRepository;
		this.metadataResolver = metadataResolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			writeSpMetadata(request, response);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	private void writeSpMetadata(HttpServletRequest request,
								 HttpServletResponse response) throws IOException {
		String alias = getIdpAlias(request);
		if (logger.isDebugEnabled()) {
			logger.debug("Creating SAML2 SP Metadata for IDP[" + alias + "]");
		}
		Assert.hasText(alias, "IDP Alias must be present and valid");
		String applicationRequestUri = getApplicationUri(request);
		Saml2IdentityProviderDetails idp = providerRepository.getIdentityProviderByAlias(alias, applicationRequestUri);
		String xml = metadataResolver.resolveServiceProviderMetadata(idp);
		response.setContentType(MediaType.APPLICATION_XML_VALUE);
		response.getWriter().write(xml);
	}

	private String getIdpAlias(HttpServletRequest request) {
		if (matcher.matches(request)) {
			return matcher.extractUriTemplateVariables(request).get("alias");
		}
		return null;

	}

}
