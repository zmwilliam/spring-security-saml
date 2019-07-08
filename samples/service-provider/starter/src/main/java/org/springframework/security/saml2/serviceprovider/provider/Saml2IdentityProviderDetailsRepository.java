package org.springframework.security.saml2.serviceprovider.provider;

/**
 * Resolves a configured remote provider by entityId or alias
 */
public interface Saml2IdentityProviderDetailsRepository {

	/**
	 * Resolves an entity provider by entityId
	 * @param entityId - unique entityId, not null
	 * @return a configured remote identity provider, or null if none found
	 */
	Saml2IdentityProviderDetails getIdentityProviderById(String entityId);

	/**
	 * Resolves an entity provider by entityId
	 * @param alias - unique alias, not null
	 * @return a configured remote identity provider, or null if none found
	 */
	Saml2IdentityProviderDetails getIdentityProviderByAlias(String alias);

}
