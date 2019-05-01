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

package org.springframework.security.saml2.serviceprovider.servlet.authentication;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.serviceprovider.authentication.DefaultSaml2Authentication;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2Authentication;
import org.springframework.security.saml2.serviceprovider.registration.Saml2IdentityProviderRegistration;
import org.springframework.security.saml2.serviceprovider.servlet.filter.Saml2IdentityProviderRepository;
import org.springframework.security.saml2.spi.OpenSaml2Implementation;
import org.springframework.security.saml2.util.Saml2KeyData;

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
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singleton;
import static org.springframework.util.StringUtils.hasText;

public class OpenSamlAuthenticationResponseResolver implements Saml2AuthenticationResponseResolver {

	private final OpenSaml2Implementation saml = new OpenSaml2Implementation().init();
	private String localSpEntityId;
	private final List<Saml2KeyData> localKeys;//used for decryption
	private Saml2IdentityProviderRepository idps;

	public OpenSamlAuthenticationResponseResolver(String localSpEntityId,
												  List<Saml2KeyData> localKeys,
												  Saml2IdentityProviderRepository idpRepository) {
		this.localSpEntityId = localSpEntityId;
		this.localKeys = localKeys;
		idps = idpRepository;
	}

	@Override
	public Saml2Authentication resolveSaml2Authentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException {
		final String responseParamName = "SAMLResponse";
		String encodedXml = request.getParameter(responseParamName);
		if (!hasText(encodedXml)) {
			throw new AuthenticationCredentialsNotFoundException(responseParamName);
		}
		String xml = decodeAndInflate(request, encodedXml);

		Response samlResponse = getSaml2Response(xml);
		Assertion assertion = validateSaml2Response(request, samlResponse);

		return extractSaml2Authentication(request, xml, samlResponse, assertion);
	}

	private Saml2Authentication extractSaml2Authentication(HttpServletRequest request,
														   String xml,
														   Response samlResponse,
														   Assertion assertion) {
		String username = assertion.getSubject().getNameID().getValue();
		return new DefaultSaml2Authentication(
			true,
			username,
			assertion,
			samlResponse.getIssuer().getValue(),
			null,
			request.getParameter("RelayState"),
			xml
		);
	}

	private Assertion validateSaml2Response(HttpServletRequest request,
											Response samlResponse) throws AuthenticationException {
		String destination = request.getRequestURL().toString();

		if (!destination.equals(samlResponse.getDestination())) {
			throw new ProviderNotFoundException("SP Not Found at: " + samlResponse.getDestination());
		}

		final String issuer = samlResponse.getIssuer().getValue();
		final Saml2IdentityProviderRegistration idp = idps.getIdentityProvider(issuer);
		boolean responseSigned = hasValidSignature(samlResponse, idp);
		for (Assertion a : samlResponse.getAssertions()) {
			if (isValidAssertion(destination, a, idp, !responseSigned)) {
				return a;
			}
		}
		throw new InsufficientAuthenticationException("Unable to find a valid assertion");
	}

	private boolean hasValidSignature(SignableSAMLObject samlResponse, Saml2IdentityProviderRegistration idp) {
		if (!samlResponse.isSigned()) {
			return false;
		}
		if (idp.getVerificationKeys().isEmpty()) {
			return false;
		}
		for (Saml2KeyData key : idp.getVerificationKeys()) {
			final Credential credential = getBasicCredential(key);
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
		validationParams.put(SAML2AssertionValidationParameters.CLOCK_SKEW, Duration.ofMinutes(5));
		validationParams.put(SAML2AssertionValidationParameters.COND_VALID_AUDIENCES, singleton(localSpEntityId));
		validationParams.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, singleton(recipient));

		if (signatureRequired && !hasValidSignature(a, idp)) {
			return false;
		}
		a.setSignature(null);

		//validation for recipient
		ValidationContext vctx = new ValidationContext(validationParams);
		try {
			final ValidationResult result = validator.validate(a, vctx);
			return result.equals(ValidationResult.VALID);
		} catch (AssertionValidationException e) {
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

	private String decodeAndInflate(HttpServletRequest request, String encodedXml) {
		byte[] b = saml.decode(encodedXml);
		if (HttpMethod.GET.matches(request.getMethod())) {
			return saml.inflate(b);
		}
		else {
			return new String(b, UTF_8);
		}
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
		for (Saml2KeyData key : provider.getVerificationKeys()) {
			final Credential cred = getBasicCredential(key);
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

	private Credential getBasicCredential(Saml2KeyData key) {
		try {
			final X509Certificate certificate = X509Support.decodeCertificate(key.getCertificate());
			return CredentialSupport.getSimpleCredential(certificate, null);
		} catch (CertificateException e) {
			throw new Saml2Exception(e);
		}
	}
}
