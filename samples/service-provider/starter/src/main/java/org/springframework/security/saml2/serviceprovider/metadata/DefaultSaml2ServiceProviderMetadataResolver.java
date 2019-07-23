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

package org.springframework.security.saml2.serviceprovider.metadata;

import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import org.springframework.security.saml2.serviceprovider.OpenSaml2Implementation;
import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetails;
import org.springframework.web.util.UriComponentsBuilder;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;

import static java.util.Arrays.asList;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage.DECRYPTION;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage.ENCRYPTION;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialUsage.SIGNING;

public class DefaultSaml2ServiceProviderMetadataResolver implements Saml2ServiceProviderMetadataResolver {

	private OpenSaml2Implementation saml = OpenSaml2Implementation.getInstance();
	private final String urlPrefix;

	public DefaultSaml2ServiceProviderMetadataResolver(String urlPrefix) {
		this.urlPrefix = urlPrefix;
	}

	@Override
	public String resolveServiceProviderMetadata(Saml2IdentityProviderDetails idp) {
		EntityDescriptor descriptor = saml.buildSAMLObject(EntityDescriptor.class);
		descriptor.setID("SPM"+ UUID.randomUUID().toString());
		descriptor.setEntityID(idp.getLocalSpEntityId());

		SPSSODescriptor spssoDescriptor = saml.buildSAMLObject(SPSSODescriptor.class);

		spssoDescriptor.setAuthnRequestsSigned(true);
		spssoDescriptor.setWantAssertionsSigned(true);

		NameIDFormat nameIdEmail = saml.buildSAMLObject(NameIDFormat.class);
		nameIdEmail.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
		NameIDFormat nameIdPersistent = saml.buildSAMLObject(NameIDFormat.class);
		nameIdPersistent.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
		NameIDFormat nameIdEncrypted = saml.buildSAMLObject(NameIDFormat.class);
		nameIdEncrypted.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted");
		spssoDescriptor.getNameIDFormats().addAll(asList(
			nameIdEmail, nameIdPersistent, nameIdEncrypted
		));

		AssertionConsumerService postSSO = saml.buildSAMLObject(AssertionConsumerService.class);
		postSSO.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		postSSO.setIndex(0);
		postSSO.setIsDefault(true);
		postSSO.setLocation(getSpSSOLocation(idp));
		AssertionConsumerService redirectSSO = saml.buildSAMLObject(AssertionConsumerService.class);
		redirectSSO.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
		redirectSSO.setIndex(1);
		redirectSSO.setIsDefault(false);
		redirectSSO.setLocation(getSpSSOLocation(idp));
		spssoDescriptor.getAssertionConsumerServices().addAll(asList(
			postSSO, redirectSSO
		));

		final List<KeyDescriptor> providerKeys = getServiceProviderKeys(idp);
		if (!providerKeys.isEmpty()) {
			spssoDescriptor.getKeyDescriptors().addAll(providerKeys);
		}

		descriptor.getRoleDescriptors().add(spssoDescriptor);

		try {
			return saml.toXml(descriptor, idp);
		} catch (MarshallingException | SignatureException | SecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private List<KeyDescriptor> getServiceProviderKeys(Saml2IdentityProviderDetails idp) {
		List<KeyDescriptor> result = new LinkedList<>();
		idp.getCredentialsForUsage(SIGNING)
			.forEach(c -> result.add(saml.getKeyDescriptor(c, SIGNING)));
		idp.getCredentialsForUsage(DECRYPTION)
			.forEach(c -> result.add(saml.getKeyDescriptor(c, ENCRYPTION)));
		return result;
	}

	private String getSpSSOLocation(Saml2IdentityProviderDetails idp) {
		return UriComponentsBuilder
			.fromHttpUrl(idp.getApplicationUri())
			.path(urlPrefix)
			.path("/SSO/")
			.path(idp.getAlias())
			.build()
			.toUriString();
	}
}
