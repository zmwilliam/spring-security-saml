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

package boot.saml2.config;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetails;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRegistration;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRepository;

import boot.saml2.config.Saml2SampleBootConverters.Saml2X509CredentialConverter;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;

@Configuration
@ConfigurationProperties(prefix = "spring.security.saml2")
public class Saml2SampleBootConfiguration {

	static {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private ServiceProvider provider;

	@Bean
	public Saml2ServiceProviderRepository saml2ServiceProviderRegistrationRepository() {
		final ServiceProvider provider = this.provider;
		return eid -> new Saml2ServiceProviderRegistration(ofNullable(provider.getEntityId()).orElse(eid),
				provider.getSaml2X509Credentials(), getIdentityProviders(provider.getIdentityProviders()));
	}

	public void setServiceProvider(ServiceProvider provider) {
		this.provider = provider;
	}

	private List<Saml2IdentityProviderDetails> getIdentityProviders(List<IdentityProvider> identityProviders) {
		return identityProviders.stream()
				.map(p -> new Saml2IdentityProviderDetails(p.getEntityId(), p.getCertificates()))
				.collect(Collectors.toList());
	}

	public static class ServiceProvider {

		private List<IdentityProvider> identityProviders = emptyList();

		private String entityId;

		private List<Saml2X509Credential> credentials = emptyList();

		public List<IdentityProvider> getIdentityProviders() {
			return identityProviders;
		}

		public void setIdentityProviders(List<IdentityProvider> identityProviders) {
			this.identityProviders = identityProviders;
		}

		public String getEntityId() {
			return entityId;
		}

		public void setEntityId(String entityId) {
			this.entityId = entityId;
		}

		public List<Saml2X509Credential> getSaml2X509Credentials() {
			return credentials;
		}

		public void setCredentials(List<StringX509Credential> credentials) {
			final Saml2X509CredentialConverter converter = new Saml2X509CredentialConverter();
			this.credentials = credentials.stream().map(c -> converter.convert(c)).collect(Collectors.toList());
		}

	}

	public static class IdentityProvider {

		private String entityId;

		private List<X509Certificate> certificates = emptyList();

		public String getEntityId() {
			return entityId;
		}

		public void setEntityId(String entityId) {
			this.entityId = entityId;
		}

		public List<X509Certificate> getCertificates() {
			return certificates;
		}

		public void setCertificates(List<X509Certificate> certificates) {
			this.certificates = certificates;
		}

	}

	public static class StringX509Credential {

		private String privateKey;

		private String passphrase;

		private String certificate;

		public String getPrivateKey() {
			return privateKey;
		}

		public void setPrivateKey(String privateKey) {
			this.privateKey = privateKey;
		}

		public String getPassphrase() {
			return passphrase;
		}

		public void setPassphrase(String passphrase) {
			this.passphrase = passphrase;
		}

		public String getCertificate() {
			return certificate;
		}

		public void setCertificate(String certificate) {
			this.certificate = certificate;
		}

	}

}
