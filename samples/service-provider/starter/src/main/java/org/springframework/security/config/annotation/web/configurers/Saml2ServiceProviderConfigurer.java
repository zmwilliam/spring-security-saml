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
import java.util.function.Supplier;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationProvider;
import org.springframework.security.saml2.serviceprovider.registration.DefaultSaml2IdentityProviderRepository;
import org.springframework.security.saml2.serviceprovider.registration.Saml2IdentityProviderDetails;
import org.springframework.security.saml2.serviceprovider.registration.Saml2IdentityProviderDetails.Saml2IdentityProviderDetailsBuilder;
import org.springframework.security.saml2.serviceprovider.registration.Saml2IdentityProviderRepository;
import org.springframework.security.saml2.serviceprovider.registration.Saml2ServiceProviderRegistration;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2AuthenticationFailureHandler;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.header.HeaderWriterFilter;

import static java.util.Optional.ofNullable;

public class Saml2ServiceProviderConfigurer extends AbstractHttpConfigurer<Saml2ServiceProviderConfigurer, HttpSecurity> {
	public static Saml2ServiceProviderConfigurer saml2Login() {
		return new Saml2ServiceProviderConfigurer();
	}

	private String spEntityId = null;
	private List<Saml2X509Credential> spCredentials = new LinkedList<>();
	private List<Saml2IdentityProviderDetails> idps = new LinkedList<>();
	private AuthenticationProvider authenticationProvider;

	public Saml2ServiceProviderConfigurer() {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public Saml2ServiceProviderConfigurer serviceProviderEntityId(String entityId) {
		this.spEntityId = entityId;
		return this;
	}

	public Saml2ServiceProviderConfigurer addServiceProviderKey(Saml2X509Credential key) {
		this.spCredentials.add(key);
		return this;
	}

	public Saml2ServiceProviderConfigurer authenticationProvider(AuthenticationProvider provider) {
		this.authenticationProvider = provider;
		return this;
	}

	public Saml2ServiceProviderConfigurer addIdentityProvider(Consumer<Saml2IdentityProviderDetailsBuilder> idp) {
		Saml2IdentityProviderDetailsBuilder ridp = Saml2IdentityProviderDetails.builder();
		idp.accept(ridp);
		this.idps.add(ridp.build());
		return this;
	}

	@Override
	public void init(HttpSecurity builder) throws Exception {
		super.init(builder);
		builder.authorizeRequests()
			.mvcMatchers("/saml/sp/**").permitAll()
			.anyRequest().authenticated();
		builder.csrf().ignoringAntMatchers("/saml/sp/**");

		if (authenticationProvider == null) {
			Saml2IdentityProviderRepository identityProviderRepository =
				getSharedObject(
					builder,
					Saml2IdentityProviderRepository.class,
					() -> new DefaultSaml2IdentityProviderRepository(idps),
					null
				);

			authenticationProvider = new Saml2AuthenticationProvider(
				new Saml2ServiceProviderRegistration(spEntityId, spCredentials),
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


	private <C> C getSharedObject(HttpSecurity http, Class<C> clazz) {
		return http.getSharedObject(clazz);
	}

	private <C> void setSharedObject(HttpSecurity http, Class<C> clazz, C object) {
		if (http.getSharedObject(clazz) == null) {
			http.setSharedObject(clazz, object);
		}
	}

	private <C> C getSharedObject(HttpSecurity http,
								  Class<C> clazz,
								  Supplier<? extends C> creator,
								  Object existingInstance) {
		C result = ofNullable((C) existingInstance).orElseGet(() -> getSharedObject(http, clazz));
		if (result == null) {
			ApplicationContext context = getSharedObject(http, ApplicationContext.class);
			try {
				result = context.getBean(clazz);
			} catch (NoSuchBeanDefinitionException e) {
				if (creator != null) {
					result = creator.get();
				}
				else {
					return null;
				}
			}
		}
		setSharedObject(http, clazz, result);
		return result;
	}
}
