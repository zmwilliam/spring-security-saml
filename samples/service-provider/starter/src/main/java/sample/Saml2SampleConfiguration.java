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

package sample;

import java.io.CharArrayReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetails;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRegistration;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRepository;
import org.springframework.util.Assert;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.opensaml.security.x509.X509Support;

import static java.util.Optional.ofNullable;

@Configuration
@ConfigurationProperties(prefix = "spring.security.saml2")
public class Saml2SampleConfiguration {
	static {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private Map<String, Object> data;

	@Bean
	public Saml2ServiceProviderRepository saml2ServiceProviderRegistrationRepository() {
		return getServiceProviderRepository();
	}

	private Saml2ServiceProviderRepository getServiceProviderRepository() {
		String entityId = (String) data.get("entity-id");
		Map<String,Object> keys = (Map<String, Object>) data.get("credentials");
		List<Saml2X509Credential> credentials = new LinkedList<>();
		for (Object key : keys.entrySet()) {
			Map<String,String> set = (Map<String,String>)((Map.Entry)key).getValue();
			String pkey = set.get("private-key");
			String passphrase = set.get("passphrase");
			String certificate = set.get("certificate");
			final PrivateKey pk = getPrivateKey(pkey, passphrase);
			final X509Certificate cert = getCertificate(certificate);
			credentials.add(new Saml2X509Credential(pk, cert));
		}
		final Saml2ServiceProviderRegistration registration = new Saml2ServiceProviderRegistration(
			entityId,
			credentials,
			getSaml2IdentityProviderDetails()
		);

		//anonymous implementation of Saml2ServiceProviderRepository
		return eid -> new Saml2ServiceProviderRegistration(
			ofNullable(registration.getEntityId()).orElse(eid),
			registration.getCredentials(),
			registration.getIdentityProviders()
		);
	}

	private List<Saml2IdentityProviderDetails> getSaml2IdentityProviderDetails() {
		final List<Saml2IdentityProviderDetails> idps = new LinkedList<>();
		Map<String,Object> keys = (Map<String, Object>) data.get("identity-providers");
		for (Object key : keys.entrySet()) {
			List<X509Certificate> certificates = new LinkedList<>();
			Map<String,Object> set = (Map<String,Object>)((Map.Entry)key).getValue();
			String entityId = (String) set.get("entity-id");
			Map<String,Object> certs = (Map<String, Object>) set.get("certificates");
			for (Object cert : certs.entrySet()) {
				String c = (String)((Map.Entry)cert).getValue();
				certificates.add(getCertificate(c));
			}
			idps.add(new Saml2IdentityProviderDetails(entityId, certificates));
		}
		return idps;
	}


	public void setServiceProvider(Map<String,Object> data) {
		this.data = data;
	}

	private X509Certificate getCertificate(String certificate) {
		try {
			return X509Support.decodeCertificate(certificate);
		} catch (CertificateException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private PrivateKey getPrivateKey(String key, String passphrase) {
		final String password = ofNullable(passphrase).orElse("");
		Assert.hasText(key, "private key cannot be empty");
		try {
			PEMParser parser = new PEMParser(new CharArrayReader(key.toCharArray()));
			Object obj = parser.readObject();
			parser.close();
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			KeyPair kp;
			if (obj == null) {
				throw new IllegalArgumentException("Unable to decode PEM key:" + key);
			}
			else if (obj instanceof PEMEncryptedKeyPair) {
				// Encrypted key - we will use provided password
				PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) obj;
				PEMDecryptorProvider decProv =
					new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
				kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
			}
			else {
				// Unencrypted key - no password needed
				PEMKeyPair ukp = (PEMKeyPair) obj;
				kp = converter.getKeyPair(ukp);
			}

			return kp.getPrivate();
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
