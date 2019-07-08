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

/**
 * Resolver of a locally configured service provider and remotely paired identity providers.
 */
public interface Saml2ServiceProviderRepository {

	/**
	 * Resolves a locally configured Service Provider, SP, based on a given entity ID
	 * A <code>null</code> value may be passed in to resolve the default provider
	 * @param serviceProviderEntityId - a unique entity ID for the local provider, or <code>null</code> to retrieve the
	 *                                default service provider
	 * @return a configured Service Provider, or null if none is found
	 */
	Saml2ServiceProviderRegistration getServiceProvider(String serviceProviderEntityId);

	/**
	 * Returns an indexed repository for configured identity providers for a locally configured service provider.
	 * @param serviceProviderEntityId a unique entity ID for the local provider, or <code>null</code> to retrieve the
	 * 	 *                            default service provider
	 * @return a repository containing the identity provider
	 */
	Saml2IdentityProviderDetailsRepository getIdentityProviders(String serviceProviderEntityId);

}
