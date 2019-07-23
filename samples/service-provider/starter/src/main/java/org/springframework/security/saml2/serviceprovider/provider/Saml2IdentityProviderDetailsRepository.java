package org.springframework.security.saml2.serviceprovider.provider;

/**
 * Resolves a configured remote provider by entityId or alias
 */
public interface Saml2IdentityProviderDetailsRepository {

	/**
	 * Resolves an entity provider by entityId
	 * @param idpEntityId - unique entityId for the remote identity provider, not null
	 * @param applicationUri - uri of the local application used to generate the local entityId, may be null
	 * @return a configured remote identity provider, or null if none found
	 */
	Saml2IdentityProviderDetails findByEntityId(String idpEntityId, String applicationUri);

	/**
	 * Resolves an entity provider by entityId
	 * @param alias - unique alias, not null
	 * @param applicationUri - uri of the local application used to generate the local entityId, may be null
	 * @return a configured remote identity provider, or null if none found
	 */
	Saml2IdentityProviderDetails findByAlias(String alias, String applicationUri);

}
