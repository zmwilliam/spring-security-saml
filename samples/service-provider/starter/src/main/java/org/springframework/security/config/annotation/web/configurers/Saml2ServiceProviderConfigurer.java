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
import java.util.Iterator;
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
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetailsRepository;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderRegistration;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2AuthenticationRequestFilter;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2LoginPageGeneratingFilter;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.util.Optional.ofNullable;

public class Saml2ServiceProviderConfigurer
		extends AbstractHttpConfigurer<Saml2ServiceProviderConfigurer, HttpSecurity> {

	public static Saml2ServiceProviderConfigurer saml2Login() {
		return new Saml2ServiceProviderConfigurer();
	}

	private AuthenticationProvider authenticationProvider;
	private Saml2IdentityProviderDetailsRepository providerDetailsRepository;
	private AuthenticationEntryPoint entryPoint = null;
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

	public Saml2ServiceProviderConfigurer identityProviderRepository(Saml2IdentityProviderDetailsRepository repo) {
		this.providerDetailsRepository = repo;
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

		providerDetailsRepository = getSharedObject(
			builder,
			Saml2IdentityProviderDetailsRepository.class,
			() -> providerDetailsRepository,
			providerDetailsRepository
		);

		if (authenticationProvider == null) {
			authenticationProvider = new Saml2AuthenticationProvider();
		}
		builder.authenticationProvider(postProcess(authenticationProvider));

		if (entryPoint != null) {
			registerDefaultAuthenticationEntryPoint(builder, entryPoint);
		} else {
			final Saml2IdentityProviderDetailsRepository idps = providerDetailsRepository;
			String alias = null;
			if (idps instanceof Iterable) {
				Iterator<Saml2IdentityProviderRegistration> it = ((Iterable<Saml2IdentityProviderRegistration>) idps).iterator();
				int count = 0;
				while (it.hasNext() && count<2) {
					count++;
					alias = it.next().getAlias();
				}
				if (count>1) {
					alias = null;
				}
			}
			String loginUrl = (alias==null) ? "/login" : "/saml/sp/authenticate/"+alias;
			registerDefaultAuthenticationEntryPoint(builder, new LoginUrlAuthenticationEntryPoint(loginUrl));
		}

		authenticationRequestResolver = getSharedObject(builder,
			Saml2AuthenticationRequestResolver.class,
			() -> new DefaultSaml2AuthenticationRequestResolver(),
			authenticationRequestResolver
		);
	}

	@Override
	public void configure(HttpSecurity builder) throws Exception {
		configureSaml2LoginPageFilter(builder, "/saml/sp/authenticate/", "/login");
		configureSaml2WebSsoAuthenticationFilter(builder, "/saml/sp/SSO/{alias}/**");
		configureSaml2AuthenticationRequestFilter(builder, "/saml/sp/authenticate/{alias}/**");
	}

	protected void configureSaml2AuthenticationRequestFilter(HttpSecurity builder, String filterUrl) {
		Filter authenticationRequestFilter = new Saml2AuthenticationRequestFilter(
			filterUrl,
			providerDetailsRepository,
			authenticationRequestResolver
		);
		builder.addFilterAfter(authenticationRequestFilter, HeaderWriterFilter.class);
	}

	protected void configureSaml2LoginPageFilter(HttpSecurity builder,
												 String authRequestPrefixUrl,
												 String loginFilterUrl) {
		Saml2IdentityProviderDetailsRepository idpRepo = providerDetailsRepository;
		Map<String,String> idps = new HashMap<>();
		if (idpRepo instanceof Iterable) {
			Iterable<Saml2IdentityProviderRegistration> repo = (Iterable<Saml2IdentityProviderRegistration>) idpRepo;
			repo.forEach(
				p -> idps.put(p.getAlias(), authRequestPrefixUrl +p.getAlias())
			);
		}
		Filter loginPageFilter =  new Saml2LoginPageGeneratingFilter(
			new AntPathRequestMatcher(loginFilterUrl), idps
		);
		builder.addFilterAfter(loginPageFilter, HeaderWriterFilter.class);
	}

	protected void configureSaml2WebSsoAuthenticationFilter(HttpSecurity builder,
															String filterUrl) {
		AuthenticationFailureHandler failureHandler =
			new SimpleUrlAuthenticationFailureHandler("/login?error=saml2-error");
		Saml2WebSsoAuthenticationFilter webSsoFilter =
			new Saml2WebSsoAuthenticationFilter(filterUrl, providerDetailsRepository);
		webSsoFilter.setAuthenticationFailureHandler(failureHandler);
		webSsoFilter.setAuthenticationManager(builder.getSharedObject(AuthenticationManager.class));
		builder.addFilterAfter(webSsoFilter, HeaderWriterFilter.class);
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
