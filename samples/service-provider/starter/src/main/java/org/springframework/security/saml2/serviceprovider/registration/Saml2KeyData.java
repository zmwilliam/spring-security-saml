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

public class Saml2KeyData {

	private final String id;
	private final String privateKey;
	private final String certificate;
	private final String passphrase;
	private final Saml2KeyType type;

	public Saml2KeyData(String id,
						String privateKey,
						String certificate,
						String passphrase,
						Saml2KeyType type) {
		this.id = id;
		this.privateKey = privateKey;
		this.certificate = certificate;
		this.passphrase = passphrase;
		this.type = type;
	}

	public String getId() {
		return id;
	}

	public Saml2KeyType getType() {
		return type;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public String getCertificate() {
		return certificate;
	}

	public String getPassphrase() {
		return passphrase;
	}

	public static Saml2KeyData signatureVerificationKey(String keyId, String certificate) {
		return new Saml2KeyData(
			keyId,
			null,
			certificate,
			null,
			Saml2KeyType.SIGNING
		);
	}

}
