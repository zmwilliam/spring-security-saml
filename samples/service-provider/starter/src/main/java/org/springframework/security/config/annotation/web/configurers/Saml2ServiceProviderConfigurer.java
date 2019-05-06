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

package org.springframework.security.config.annotation.web.configurers;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.serviceprovider.registration.Saml2IdentityProviderRegistration;
import org.springframework.security.saml2.serviceprovider.registration.Saml2IdentityProviderRepository;
import org.springframework.security.saml2.serviceprovider.registration.Saml2KeyData;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationProvider;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2AuthenticationFailureHandler;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.header.HeaderWriterFilter;

public class Saml2ServiceProviderConfigurer extends AbstractHttpConfigurer<Saml2ServiceProviderConfigurer, HttpSecurity> {
	public static Saml2ServiceProviderConfigurer saml2Login() {
		return new Saml2ServiceProviderConfigurer();
	}

	private String serviceProviderEntityId = null;
	private List<Saml2KeyData> serviceProviderKeys = new LinkedList<>();
	private List<Saml2IdentityProviderRegistration> providers = new LinkedList<>();
	private AuthenticationProvider authenticationProvider;

	public Saml2ServiceProviderConfigurer serviceProviderEntityId(String entityId) {
		this.serviceProviderEntityId = entityId;
		return this;
	}

	public Saml2ServiceProviderConfigurer addServiceProviderKey(Saml2KeyData key) {
		serviceProviderKeys.add(key);
		return this;
	}

	public Saml2ServiceProviderConfigurer authenticationProvider(AuthenticationProvider provider) {
		this.authenticationProvider = provider;
		return this;
	}

	public Saml2ServiceProviderConfigurer addIdentityProvider(Consumer<Saml2IdentityProviderRegistration> idp) {
		Saml2IdentityProviderRegistration ridp = new Saml2IdentityProviderRegistration();
		idp.accept(ridp);
		this.providers.add(ridp);
		return this;
	}

	@Override
	public void init(HttpSecurity builder) throws Exception {
		super.init(builder);
		builder.authorizeRequests()
			.mvcMatchers("/saml/sp/**").permitAll()
			.anyRequest().authenticated();
		builder.csrf().ignoringAntMatchers("/saml/sp/**");

		Saml2IdentityProviderRepository identityProviderRepository = new Saml2IdentityProviderRepository(providers);
		if (authenticationProvider == null) {
			authenticationProvider =
				new Saml2AuthenticationProvider(
					serviceProviderEntityId,
					serviceProviderKeys,
					identityProviderRepository
				);
		}

		builder.authenticationProvider(postProcess(authenticationProvider));
	}

	@Override
	public void configure(HttpSecurity builder) throws Exception {
		Saml2AuthenticationFailureHandler failureHandler = new Saml2AuthenticationFailureHandler();
		Saml2WebSsoAuthenticationFilter filter = new Saml2WebSsoAuthenticationFilter("/saml/sp/SSO/**");
		filter.setAuthenticationFailureHandler(failureHandler);
		filter.setAuthenticationManager(builder.getSharedObject(AuthenticationManager.class));
		builder.addFilterAfter(filter, HeaderWriterFilter.class);
	}
}
