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

package org.springframework.security.saml2.serviceprovider.authentication;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.serviceprovider.registration.Saml2KeyPair;
import org.springframework.security.saml2.serviceprovider.registration.Saml2ServiceProviderRegistration;
import org.springframework.security.saml2.serviceprovider.registration.Saml2ServiceProviderRegistration.Saml2IdentityProviderRegistration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.assertion.ValidationResult;
import org.opensaml.saml.saml2.assertion.ConditionValidator;
import org.opensaml.saml.saml2.assertion.SAML20AssertionValidator;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.assertion.StatementValidator;
import org.opensaml.saml.saml2.assertion.SubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.AudienceRestrictionConditionValidator;
import org.opensaml.saml.saml2.assertion.impl.BearerSubjectConfirmationValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import static java.lang.String.format;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;

public class Saml2AuthenticationProvider implements AuthenticationProvider {

	private static Log logger = LogFactory.getLog(Saml2AuthenticationProvider.class);

	private final OpenSaml2Implementation saml = new OpenSaml2Implementation().init();
	private final Saml2ServiceProviderRegistration serviceProvider;
	private GrantedAuthoritiesMapper authoritiesMapper = (a -> a);
	private int clockSkewMillis = 1000 * 60 * 5; //5 minutes

	public Saml2AuthenticationProvider(Saml2ServiceProviderRegistration serviceProvider) {
		this.serviceProvider = serviceProvider;
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	public void setClockSkewMillis(int clockSkewMillis) {
		this.clockSkewMillis = clockSkewMillis;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication == null && !supports(authentication.getClass())) {
			throw new AuthenticationCredentialsNotFoundException("Invalid authentication type:" + authentication);
		}

		Saml2AuthenticationToken token = (Saml2AuthenticationToken) authentication;
		String xml = token.getSaml2Response();
		Response samlResponse = getSaml2Response(xml);
		Assertion assertion = validateSaml2Response(token.getRecipientUrl(), samlResponse);

		final String username = getUsername(assertion);
		if (username == null) {
			throw new UsernameNotFoundException("Assertion ["+assertion.getID()+"] is missing a user identifier");
		}
		return new Saml2AuthenticationToken(
			token.getSaml2Response(),
			() -> username,
			authoritiesMapper.mapAuthorities(getAssertionAuthorities(assertion))
		);
	}

	protected List<? extends GrantedAuthority> getAssertionAuthorities(Assertion assertion) {
		return singletonList(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication != null &&
			Saml2AuthenticationToken.class.isAssignableFrom(authentication);
	}

	private String getUsername(Assertion assertion) {
		final Subject subject = assertion.getSubject();
		if (subject == null) {
			return null;
		}
		if (subject.getNameID() != null) {
			return subject.getNameID().getValue();
		}
		if (subject.getEncryptedID() != null) {
			for (Saml2KeyPair key : serviceProvider.getSaml2Keys()) {
				try {
					NameID nameId = decrypt(subject.getEncryptedID());
					return nameId.getValue();
				} catch (Saml2Exception e) {
					logger.debug("Unable to decrypt encrypted NameID for assertion["+assertion.getID()+"]");
				}
			}
		}
		return null;
	}

	private Assertion validateSaml2Response(String recipient,
											Response samlResponse) throws AuthenticationException {
		if (!recipient.equals(samlResponse.getDestination())) {
			throw new ProviderNotFoundException("SP Not Found at: " + samlResponse.getDestination());
		}

		final String issuer = samlResponse.getIssuer().getValue();
		logger.debug("Processing SAML response from "+issuer);
		final Saml2IdentityProviderRegistration idp = serviceProvider.getIdentityProvider(issuer);
		if (idp == null) {
			throw new ProviderNotFoundException(format("SAML 2 Provider for %s was not found.", issuer));
		}
		boolean responseSigned = hasValidSignature(samlResponse, idp);
		for (Assertion a : samlResponse.getAssertions()) {
			if (isValidAssertion(recipient, a, idp, !responseSigned)) {
				return a;
			}
		}
		for (EncryptedAssertion ea : samlResponse.getEncryptedAssertions()) {
			Assertion a = decrypt(ea);
			if (isValidAssertion(recipient, a, idp, false)) {
				return a;
			}
		}
		throw new InsufficientAuthenticationException("Unable to find a valid assertion");
	}

	private boolean hasValidSignature(SignableSAMLObject samlResponse,
									  Saml2IdentityProviderRegistration idp) {
		if (!samlResponse.isSigned()) {
			return false;
		}
		if (idp.getVerificationKeys().isEmpty()) {
			return false;
		}
		for (X509Certificate key : idp.getVerificationKeys()) {
			final Credential credential = getVerificationCredential(key);
			try {
				SignatureValidator.validate(samlResponse.getSignature(), credential);
				return true;
			} catch (SignatureException ignored) {
			}
		}
		return false;
	}

	private boolean isValidAssertion(String recipient,
									 Assertion a,
									 Saml2IdentityProviderRegistration idp,
									 boolean signatureRequired) {
		final SAML20AssertionValidator validator = getAssertionValidator(idp);
		Map<String, Object> validationParams = new HashMap<>();
		validationParams.put(SAML2AssertionValidationParameters.SIGNATURE_REQUIRED, false);
		validationParams.put(SAML2AssertionValidationParameters.CLOCK_SKEW, Duration.ofMillis(clockSkewMillis));
		validationParams.put(
			SAML2AssertionValidationParameters.COND_VALID_AUDIENCES,
			singleton(serviceProvider.getEntityId())
		);
		validationParams.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, singleton(recipient));

		if (signatureRequired && !hasValidSignature(a, idp)) {
			logger.debug(format("Assertion [%s] does not a valid signature.", a.getID()));
			return false;
		}
		a.setSignature(null);

		//validation for recipient
		ValidationContext vctx = new ValidationContext(validationParams);
		try {
			final ValidationResult result = validator.validate(a, vctx);
			return result.equals(ValidationResult.VALID);
		} catch (AssertionValidationException e) {
			logger.debug("Failed to validate assertion:", e);
			return false;
		}

	}

	private Response getSaml2Response(String xml) throws Saml2Exception, AuthenticationException {
		final Object result = saml.resolve(xml);
		if (result == null) {
			throw new AuthenticationCredentialsNotFoundException("SAMLResponse returned null object");
		}
		else if (result instanceof Response) {
			return (Response) result;
		}
		throw new ClassCastException(result.getClass().getName());
	}

	private SAML20AssertionValidator getAssertionValidator(Saml2IdentityProviderRegistration provider) {
		List<ConditionValidator> conditions = Collections.singletonList(
			new AudienceRestrictionConditionValidator()
		);
		final BearerSubjectConfirmationValidator subjectConfirmationValidator =
			new BearerSubjectConfirmationValidator();

		List<SubjectConfirmationValidator> subjects = Collections.singletonList(subjectConfirmationValidator);
		List<StatementValidator> statements = Collections.emptyList();

		Set<Credential> credentials = new HashSet<>();
		for (X509Certificate key : provider.getVerificationKeys()) {
			final Credential cred = getVerificationCredential(key);
			credentials.add(cred);
		}
		CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
		SignatureTrustEngine signatureTrustEngine = new ExplicitKeySignatureTrustEngine(
			credentialsResolver,
			DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
		);
		SignaturePrevalidator signaturePrevalidator = new SAMLSignatureProfileValidator();
		;
		return new SAML20AssertionValidator(
			conditions,
			subjects,
			statements,
			signatureTrustEngine,
			signaturePrevalidator
		);
	}

	private Credential getVerificationCredential(X509Certificate certificate) {
		return CredentialSupport.getSimpleCredential(certificate, null);
	}

	private Decrypter getDecrypter(Saml2KeyPair key) {
		Credential credential = CredentialSupport.getSimpleCredential(key.getCertificate(), key.getPrivateKey());
		KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
		Decrypter decrypter = new Decrypter(null, resolver, saml.getEncryptedKeyResolver());
		decrypter.setRootInNewDocument(true);
		return decrypter;
	}

	private Assertion decrypt(EncryptedAssertion assertion) {
		Saml2Exception last = null;
		for (Saml2KeyPair key : serviceProvider.getSaml2Keys()) {
			final Decrypter decrypter = getDecrypter(key);
			try {
				return decrypter.decrypt(assertion);
			} catch (DecryptionException e) {
				throw new Saml2Exception(e);
			}
		}
		throw last;
	}

	private NameID decrypt(EncryptedID assertion) {
		Saml2Exception last = null;
		for (Saml2KeyPair key : serviceProvider.getSaml2Keys()) {
			final Decrypter decrypter = getDecrypter(key);
			try {
				return (NameID) decrypter.decrypt(assertion);
			} catch (DecryptionException e) {
				last = new Saml2Exception(e);
			}
		}
		throw last;
	}

}
