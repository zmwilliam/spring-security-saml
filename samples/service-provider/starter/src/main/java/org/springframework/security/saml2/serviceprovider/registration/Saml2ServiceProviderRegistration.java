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
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class Saml2ServiceProviderRegistration {

	private String entityId;
	private List<Saml2KeyPair> keys = new LinkedList<>();
	private Map<String, Saml2IdentityProviderRegistration> idps = new LinkedHashMap<>();

	public Saml2ServiceProviderRegistration() {
	}

	public void addIdentityProvider(Saml2IdentityProviderRegistration idp) {
		this.idps.put(idp.getEntityId(), idp);
	}

	public Saml2IdentityProviderRegistration getIdentityProvider(String entityId) {
		return idps.get(entityId);
	}

	public void addSaml2Key(Saml2KeyPair key) {
		this.keys.add(key);
	}

	public List<Saml2KeyPair> getSaml2Keys() {
		return keys;
	}

	public String getEntityId() {
		return entityId;
	}

	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}

	/**
	 * Configuration object that represents an external identity provider
	 */
	public static class Saml2IdentityProviderRegistration {

		private String alias;
		private String linktext;
		private String entityId;
		private List<X509Certificate> verificationKeys;

		public Saml2IdentityProviderRegistration() {
		}

		public String getAlias() {
			return alias;
		}

		public void setAlias(String alias) {
			this.alias = alias;
		}

		public String getLinktext() {
			return linktext;
		}

		public void setLinktext(String linktext) {
			this.linktext = linktext;
		}

		public String getEntityId() {
			return entityId;
		}

		public void setEntityId(String entityId) {
			this.entityId = entityId;
		}

		public List<X509Certificate> getVerificationKeys() {
			return verificationKeys;
		}

		public void setVerificationKeys(List<X509Certificate> verificationKeys) {
			this.verificationKeys = verificationKeys;
		}
	}

}
