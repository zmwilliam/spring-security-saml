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

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class RelyingPartyAliasUrlRequestMatcher implements Saml2RequestMatcher {

	private final AntPathRequestMatcher filterProcessesMatcher;
	private final AntPathRequestMatcher aliasExtractor;
	private final String aliasParameter;

	public RelyingPartyAliasUrlRequestMatcher(String filterProcessesUrl,
											  String aliasExtractorUrl) {
		this.filterProcessesMatcher = new AntPathRequestMatcher(filterProcessesUrl);
		this.aliasExtractor = new AntPathRequestMatcher(aliasExtractorUrl);
		this.aliasParameter = "alias";
	}

	@Override
	public String getRelyingPartyAlias(HttpServletRequest request) {
		if (aliasExtractor.matches(request)) {
			return aliasExtractor.extractUriTemplateVariables(request).get(aliasParameter);
		}
		return null;
	}

	@Override
	public String getPattern() {
		return filterProcessesMatcher.getPattern();
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return filterProcessesMatcher.matches(request);
	}
}
