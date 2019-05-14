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

import java.util.LinkedList;
import java.util.List;


/**
 * Configuration object that represents a local(hosted) service provider
 */
public class Saml2ServiceProviderRegistration {

	private final String entityId;
	private final List<Saml2X509Credential> credentials = new LinkedList<>();

	public static Saml2ServiceProviderRegistrationBuilder builder() {
		return new Saml2ServiceProviderRegistrationBuilder();
	}

	public static Saml2ServiceProviderRegistrationBuilder builder(Saml2ServiceProviderRegistration registration) {
		return builder()
			.credentials(registration.getSaml2Credentials())
			.entityId(registration.getEntityId());
	}

	private Saml2ServiceProviderRegistration(String entityId,
											List<Saml2X509Credential> credentials) {
		this.entityId = entityId;
		this.credentials.addAll(credentials);
	}

	public List<Saml2X509Credential> getSaml2Credentials() {
		return credentials;
	}

	public String getEntityId() {
		return entityId;
	}

	public static final class Saml2ServiceProviderRegistrationBuilder {
		private String entityId;
		private List<Saml2X509Credential> credentials = new LinkedList<>();

		private Saml2ServiceProviderRegistrationBuilder() {
		}

		public Saml2ServiceProviderRegistrationBuilder entityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		public Saml2ServiceProviderRegistrationBuilder credentials(List<Saml2X509Credential> keys) {
			this.credentials = keys;
			return this;
		}

		public void credential(Saml2X509Credential key) {
			this.credentials.add(key);
		}

		public Saml2ServiceProviderRegistration build() {
			Saml2ServiceProviderRegistration saml2ServiceProviderRegistration = new Saml2ServiceProviderRegistration(
				entityId,
				credentials
			);
			return saml2ServiceProviderRegistration;
		}
	}

}
