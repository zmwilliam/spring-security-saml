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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.saml2.serviceprovider.registration.Saml2IdentityProviderRegistration;

public class Saml2IdentityProviderRepository {

	private Map<String, Saml2IdentityProviderRegistration> providers = new HashMap<>();

	public Saml2IdentityProviderRepository(List<Saml2IdentityProviderRegistration> providers) {
		providers.stream().forEach(
			p -> this.providers.put(p.getEntityId(), p)
		);
	}

	public Saml2IdentityProviderRegistration getIdentityProvider(String entityId) {
		return providers.get(entityId);
	}

}
