package org.springframework.security.saml2.serviceprovider.provider;

public interface Saml2IdentityProviderDetailsRepository {

	Saml2IdentityProviderDetails getIdentityProviderById(String id);

	Saml2IdentityProviderDetails getIdentityProviderByAlias(String alias);

}
