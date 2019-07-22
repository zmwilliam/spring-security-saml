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

import org.springframework.security.saml2.serviceprovider.provider.Saml2IdentityProviderDetails;

public interface Saml2ServiceProviderMetadataResolver {
	/**
	 * Creates an authentication request from the Service Provider, sp,
	 * to the Identity Provider, idp.
	 * The authentication result is an XML string that may be signed, encrypted, both or neither.
	 * @param idp - the identity provider, the recipient of this authentication request
	 * @return XML data in the format of a String. This data may be signed, encrypted, both signed and encrypted or neither signed and encrypted
	 */
	String resolveServiceProviderMetadata(Saml2IdentityProviderDetails idp);
}
