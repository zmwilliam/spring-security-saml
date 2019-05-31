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

package org.springframework.security.saml2.serviceprovider.registration;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DefaultSaml2IdentityProviderDetailsRepository implements Saml2IdentityProviderDetailsRepository {

	private Map<String, Saml2IdentityProviderDetails> idps = new LinkedHashMap<>();

	public DefaultSaml2IdentityProviderDetailsRepository(List<Saml2IdentityProviderDetails> idps) {
		idps.stream().forEach(
			idp -> this.idps.put(idp.getEntityId(), idp)
		);
	}

	public Saml2IdentityProviderDetails getIdentityProvider(String entityId) {
		return idps.get(entityId);
	}
}
