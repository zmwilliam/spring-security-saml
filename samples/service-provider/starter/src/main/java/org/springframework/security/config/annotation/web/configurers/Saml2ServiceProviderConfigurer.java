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

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import javax.servlet.Filter;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.serviceprovider.authentication.DefaultSaml2AuthenticationRequestResolver;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationProvider;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRegistration;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRepository;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2AuthenticationFailureHandler;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2AuthenticationRequestFilter;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2LoginPageGeneratingFilter;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.util.Optional.ofNullable;

public class Saml2ServiceProviderConfigurer
		extends AbstractHttpConfigurer<Saml2ServiceProviderConfigurer, HttpSecurity> {

	public static Saml2ServiceProviderConfigurer saml2Login() {
		return new Saml2ServiceProviderConfigurer();
	}

	private AuthenticationProvider authenticationProvider;
	private Saml2ServiceProviderRepository serviceProviderRepository;
	private AuthenticationEntryPoint entryPoint;
	private Saml2AuthenticationRequestResolver authenticationRequestResolver;

	static {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public Saml2ServiceProviderConfigurer authenticationProvider(AuthenticationProvider provider) {
		this.authenticationProvider = provider;
		return this;
	}

	public Saml2ServiceProviderConfigurer authenticationRequestResolver(Saml2AuthenticationRequestResolver resolver) {
		this.authenticationRequestResolver = resolver;
		return this;
	}

	public Saml2ServiceProviderConfigurer serviceProviderRepository(Saml2ServiceProviderRepository sp) {
		this.serviceProviderRepository = sp;
		return this;
	}

	public Saml2ServiceProviderConfigurer authenticationEntryPoint(AuthenticationEntryPoint ep) {
		this.entryPoint = ep;
		return this;
	}

	@Override
	public void init(HttpSecurity builder) throws Exception {
		super.init(builder);
		builder.authorizeRequests().mvcMatchers("/saml/sp/**").permitAll().anyRequest().authenticated();
		builder.csrf().ignoringAntMatchers("/saml/sp/**");

		if (authenticationProvider == null) {
			serviceProviderRepository = getSharedObject(builder, Saml2ServiceProviderRepository.class,
					() -> serviceProviderRepository, serviceProviderRepository);
			authenticationProvider = new Saml2AuthenticationProvider(serviceProviderRepository);
		}
		builder.authenticationProvider(postProcess(authenticationProvider));

		if (entryPoint != null) {
			registerDefaultAuthenticationEntryPoint(builder, entryPoint);
		}

		authenticationRequestResolver = getSharedObject(builder,
			Saml2AuthenticationRequestResolver.class,
			() -> new DefaultSaml2AuthenticationRequestResolver(),
			authenticationRequestResolver
		);
	}

	@Override
	public void configure(HttpSecurity builder) throws Exception {
		Saml2AuthenticationFailureHandler failureHandler = new Saml2AuthenticationFailureHandler();
		Saml2WebSsoAuthenticationFilter filter = new Saml2WebSsoAuthenticationFilter("/saml/sp/SSO/**");
		filter.setAuthenticationFailureHandler(failureHandler);
		filter.setAuthenticationManager(builder.getSharedObject(AuthenticationManager.class));
		builder.addFilterAfter(filter, HeaderWriterFilter.class);
		Filter loginPageFilter = getLoginPageGeneratingFilter();
		builder.addFilterBefore(loginPageFilter, filter.getClass());
		Filter authenticationRequestFilter = new Saml2AuthenticationRequestFilter(
			new AntPathRequestMatcher("/saml/sp/authenticate/*"),
			serviceProviderRepository,
			authenticationRequestResolver
		);
		builder.addFilterAfter(authenticationRequestFilter, loginPageFilter.getClass());
	}

	private Filter getLoginPageGeneratingFilter() {
		Saml2ServiceProviderRegistration sp = serviceProviderRepository.getServiceProvider(null);
		Map<String,String> idps = new HashMap<>();
		sp.getIdentityProviders()
			.stream()
			.forEach(p -> idps.put(p.getAlias(),"/saml/sp/authenticate/"+p.getAlias()));
		return new Saml2LoginPageGeneratingFilter(
			new AntPathRequestMatcher("/login"), idps
		);
	}

	private <C> C getSharedObject(HttpSecurity http, Class<C> clazz) {
		return http.getSharedObject(clazz);
	}

	private <C> void setSharedObject(HttpSecurity http, Class<C> clazz, C object) {
		if (http.getSharedObject(clazz) == null) {
			http.setSharedObject(clazz, object);
		}
	}

	private <C> C getSharedObject(HttpSecurity http, Class<C> clazz, Supplier<? extends C> creator,
			Object existingInstance) {
		C result = ofNullable((C) existingInstance).orElseGet(() -> getSharedObject(http, clazz));
		if (result == null) {
			ApplicationContext context = getSharedObject(http, ApplicationContext.class);
			try {
				result = context.getBean(clazz);
			}
			catch (NoSuchBeanDefinitionException e) {
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

	@SuppressWarnings("unchecked")
	private void registerDefaultAuthenticationEntryPoint(HttpSecurity http, AuthenticationEntryPoint entryPoint) {
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
			http.getConfigurer(ExceptionHandlingConfigurer.class);

		if (exceptionHandling == null) {
			return;
		}

		exceptionHandling.authenticationEntryPoint(entryPoint);
	}

}
