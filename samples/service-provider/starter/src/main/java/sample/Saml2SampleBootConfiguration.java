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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRegistration;
import org.springframework.security.saml2.serviceprovider.provider.Saml2ServiceProviderRepository;

import static java.util.Optional.ofNullable;

@Configuration
@ConfigurationProperties(prefix = "spring.security.saml2")
public class Saml2SampleBootConfiguration {
	static {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private Saml2ServiceProviderRegistration provider;

	@Bean
	public Saml2ServiceProviderRepository saml2ServiceProviderRegistrationRepository() {
		return eid -> new Saml2ServiceProviderRegistration(
			ofNullable(provider.getEntityId()).orElse(eid),
			provider.getCredentials(),
			provider.getIdentityProviders()
		);
	}

	public void setServiceProvider(Saml2ServiceProviderRegistration provider) {
		this.provider = provider;
	}

}
