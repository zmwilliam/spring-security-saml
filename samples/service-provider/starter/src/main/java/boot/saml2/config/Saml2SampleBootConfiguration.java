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

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.serviceprovider.provider.InMemorySaml2IdentityProviderDetailsRepository;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetailsRepository;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderRegistration;

import boot.saml2.config.Saml2SampleBootConverters.Saml2X509CredentialConverter;

import static java.util.Collections.emptyList;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage.ENCRYPTION;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage.VERIFICATION;

@Configuration
@ConfigurationProperties(prefix = "spring.security.saml2.login")
@Import(Saml2SampleBootConverters.class)
public class Saml2SampleBootConfiguration {

	static {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private List<IdentityProvider> providers;

	@Bean
	public Saml2IdentityProviderDetailsRepository saml2IdentityProviderDetailsRepository() {
		InMemorySaml2IdentityProviderDetailsRepository idpRepo =
			new InMemorySaml2IdentityProviderDetailsRepository(getIdentityProviders(providers));
		return idpRepo;
	}

	public void setIdentityProviders(List<IdentityProvider> providers) {
		this.providers = providers;
	}

	private List<Saml2IdentityProviderRegistration> getIdentityProviders(List<IdentityProvider> identityProviders) {
		return identityProviders.stream()
				.map(
					p -> new Saml2IdentityProviderRegistration(
						p.getEntityId(),
						p.getAlias(),
						p.getWebSsoUrlAsURI(),
						p.getProviderCredentials(),
						p.getLocalEntityId()
					)
				)
				.collect(Collectors.toList());
	}

	public static class IdentityProvider {

		private String entityId;
		private List<Saml2X509Credential> signingCredentials = emptyList();
		private List<X509Certificate> verificationCredentials = emptyList();
		private String alias;
		private String webSsoUrl;
		private String localEntityId;

		public String getEntityId() {
			return entityId;
		}

		public String getLocalEntityId() {
			return localEntityId;
		}

		public void setEntityId(String entityId) {
			this.entityId = entityId;
		}

		public List<Saml2X509Credential> getSigningCredentials() {
			return signingCredentials;
		}

		public void setSigningCredentials(List<StringX509Credential> credentials) {
			final Saml2X509CredentialConverter converter = new Saml2X509CredentialConverter();
			this.signingCredentials = credentials.stream().map(c -> converter.convert(c)).collect(Collectors.toList());
		}

		public void setVerificationCredentials(List<X509Certificate> credentials) {
			this.verificationCredentials = new LinkedList<>(credentials);
		}

		public List<X509Certificate> getVerificationCredentials() {
			return verificationCredentials;
		}

		public List<Saml2X509Credential> getProviderCredentials() {
			LinkedList<Saml2X509Credential> result = new LinkedList<>(getSigningCredentials());
			for (X509Certificate c : getVerificationCredentials()) {
				result.add(new Saml2X509Credential(null, c, ENCRYPTION, VERIFICATION));
			}
			return result;
		}

		public String getAlias() {
			return alias;
		}

		public IdentityProvider setAlias(String alias) {
			this.alias = alias;
			return this;
		}

		public String getWebSsoUrl() {
			return webSsoUrl;
		}

		public URI getWebSsoUrlAsURI() {
			try {
				return new URI(webSsoUrl);
			} catch (URISyntaxException e) {
				throw new IllegalArgumentException(e);
			}
		}

		public IdentityProvider setWebSsoUrl(String webSsoUrl) {
			this.webSsoUrl = webSsoUrl;
			return this;
		}

		public void setLocalEntityId(String localEntityId) {
			this.localEntityId = localEntityId;
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
