/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml2.registration;

import java.util.LinkedList;
import java.util.List;

import org.springframework.util.Assert;

import static org.springframework.util.StringUtils.hasText;

/**
 * Immutable configuration object that represents an external identity provider
 */
public class ExternalSaml2IdentityProviderRegistration extends
	ExternalSaml2ProviderRegistration<ExternalSaml2IdentityProviderRegistration> {


	public ExternalSaml2IdentityProviderRegistration(String alias,
													 String linktext,
													 String entityId,
													 List<Saml2KeyData> verificationKeys) {
		super(alias, linktext, entityId, verificationKeys);
	}

	public static Builder builder() {
		return new Builder();
	}

	public static Builder builder(ExternalSaml2IdentityProviderRegistration idp) {
		return builder()
			.alias(idp.getAlias())
			.linktext(idp.getLinktext())
			.verificationKeys(idp.getVerificationKeys())
			;

	}

	public static final class Builder {
		private String alias;
		private String entityId;
		private String linktext;
		private List<Saml2KeyData> verificationKeys = new LinkedList<>();

		private Builder() {
		}

		public Builder alias(String alias) {
			this.alias = alias;
			return this;
		}

		public Builder entityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		public Builder linktext(String linktext) {
			this.linktext = linktext;
			return this;
		}

		public Builder verificationKeys(List<Saml2KeyData> verificationKeys) {
			this.verificationKeys = new LinkedList<>(verificationKeys);
			return this;
		}

		public Builder addVerificationKey(Saml2KeyData verificationKey) {
			this.verificationKeys.add(verificationKey);
			return this;
		}


		public ExternalSaml2IdentityProviderRegistration build() {
			Assert.notNull(alias, "Alias is required");
			Assert.notNull(entityId, "EntityId is required");
			return new ExternalSaml2IdentityProviderRegistration(
				alias,
				hasText(linktext) ? linktext : alias,
				entityId,
				verificationKeys
			);
		}
	}
}
