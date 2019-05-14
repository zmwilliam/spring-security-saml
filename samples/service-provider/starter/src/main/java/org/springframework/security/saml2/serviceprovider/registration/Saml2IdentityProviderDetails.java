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

/**
 * Configuration object that represents an external identity provider
 */
public class Saml2IdentityProviderDetails {

	private final String alias;
	private final String entityId;
	private final List<X509Certificate> verificationCredentials;
	private final String linktext;

	public static Saml2IdentityProviderDetailsBuilder builder() {
		return new Saml2IdentityProviderDetailsBuilder();
	}

	public static Saml2IdentityProviderDetailsBuilder builder(Saml2IdentityProviderDetails details) {
		return builder()
			.alias(details.getAlias())
			.entityId(details.getEntityId())
			.verificationCredentials(details.getVerificationCredentials())
			.linktext(details.getLinktext());
	}

	private Saml2IdentityProviderDetails(String alias,
										String entityId,
										List<X509Certificate> verificationCredentials,
										String linktext) {
		this.alias = alias;
		this.entityId = entityId;
		this.verificationCredentials = verificationCredentials;
		this.linktext = linktext;
	}

	public String getAlias() {
		return alias;
	}

	public String getLinktext() {
		return linktext;
	}

	public String getEntityId() {
		return entityId;
	}

	public List<X509Certificate> getVerificationCredentials() {
		return verificationCredentials;
	}


	public static final class Saml2IdentityProviderDetailsBuilder {
		private String alias;
		private String entityId;
		private List<X509Certificate> verificationCredentials;
		private String linktext;

		private Saml2IdentityProviderDetailsBuilder() {
		}

		public Saml2IdentityProviderDetailsBuilder alias(String alias) {
			this.alias = alias;
			return this;
		}

		public Saml2IdentityProviderDetailsBuilder entityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		public Saml2IdentityProviderDetailsBuilder verificationCredentials(List<X509Certificate> verificationCredentials) {
			this.verificationCredentials = verificationCredentials;
			return this;
		}

		public Saml2IdentityProviderDetailsBuilder linktext(String linktext) {
			this.linktext = linktext;
			return this;
		}

		public Saml2IdentityProviderDetails build() {
			return new Saml2IdentityProviderDetails(alias, entityId, verificationCredentials, linktext);
		}
	}
}
