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

import java.security.cert.X509Certificate;
import java.util.List;

import static org.springframework.util.Assert.notEmpty;
import static org.springframework.util.Assert.notNull;

/**
 * Configuration object that represents an external identity provider
 */
public class Saml2IdentityProviderDetails {

	private final String entityId;
	private final List<X509Certificate> verificationCredentials;

	public Saml2IdentityProviderDetails(String entityId,
										 List<X509Certificate> verificationCredentials) {
		notNull(entityId, "entityId is required");
		notEmpty(verificationCredentials, "verification credentials are required");
		verificationCredentials.stream().forEach(c -> notNull(c, "verification credentials cannot be null"));
		this.entityId = entityId;
		this.verificationCredentials = verificationCredentials;
	}

	public String getEntityId() {
		return entityId;
	}

	public List<X509Certificate> getVerificationCredentials() {
		return verificationCredentials;
	}


}
