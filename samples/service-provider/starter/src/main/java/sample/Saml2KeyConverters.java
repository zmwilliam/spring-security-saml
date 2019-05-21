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
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import static java.util.Optional.ofNullable;

class Saml2KeyConverters {

	/**
	 * Construct a {@link Converter} for converting a PEM-encoded PKCS#8 RSA Private Key
	 * into a {@link RSAPrivateKey}.
	 *
	 * Note that keys are often formatted in PKCS#1 and this can easily be identified by the header.
	 * If the key file begins with "-----BEGIN RSA PRIVATE KEY-----", then it is PKCS#1. If it is
	 * PKCS#8 formatted, then it begins with "-----BEGIN PRIVATE KEY-----".
	 *
	 * This converter does not close the {@link InputStream} in order to avoid making non-portable
	 * assumptions about the streams' origin and further use.
	 *
	 * @param passphrase - (optional) if the key is encrypted, provide the passphrase to decrypt the key.
	 * @return A {@link Converter} that can read a PEM-encoded PKCS#8 RSA Private Key and return a
	 * {@link PrivateKey}.
	 */
	static Converter<CharSequence, PrivateKey> pkcs8(String passphrase) {

		return source -> {
			final String password = ofNullable(passphrase).orElse("");
			String key = source.toString();
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
		};
	}
}
