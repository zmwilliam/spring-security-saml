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
package org.springframework.security.saml2.serviceprovider.samples;

import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.joda.time.DateTime;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.w3c.dom.Element;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml2.serviceprovider.samples.SAML2ActionTestingSupport.buildConditions;
import static org.springframework.security.saml2.serviceprovider.samples.SAML2ActionTestingSupport.buildIssuer;
import static org.springframework.security.saml2.serviceprovider.samples.SAML2ActionTestingSupport.buildSubject;
import static org.springframework.security.saml2.serviceprovider.samples.SAML2ActionTestingSupport.buildSubjectConfirmation;
import static org.springframework.security.saml2.serviceprovider.samples.SAML2ActionTestingSupport.buildSubjectConfirmationData;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SAML 2 Login Tests")
public class ServiceProviderSampleTests {

	public static final String LOCAL_SP_ENTITY_ID = "http://localhost:8080/sample-sp";
	@Autowired
	MockMvc mockMvc;

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "org/springframework/security/saml2/serviceprovider/samples")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("test signed response")
	void signedResponse() throws Exception {
		Assertion assertion = buildAssertion();
		Response response = buildResponse(assertion);
		signXmlObject(response, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		String xml = toXml(response);
		mockMvc.perform(
			post("http://localhost:8080/sample-sp/saml/sp/SSO/alias/localhost")
				.contextPath("/sample-sp")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param("SAMLResponse", Saml2TestUtils.encode(xml.getBytes(UTF_8)))
		)
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/sample-sp/"))
			.andExpect(authenticated());
	}

	@Test
	@DisplayName("test signed assertion")
	void signedAssertion() throws Exception {
		Assertion assertion = buildAssertion();
		Response response = buildResponse(assertion);
		signXmlObject(assertion, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		String xml = toXml(response);
		mockMvc.perform(
			post("http://localhost:8080/sample-sp/saml/sp/SSO/alias/localhost")
				.contextPath("/sample-sp")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param("SAMLResponse", Saml2TestUtils.encode(xml.getBytes(UTF_8)))
		)
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/sample-sp/"))
			.andExpect(authenticated());
	}

	private Response buildResponse(Assertion assertion) {
		Response response = SAML2ActionTestingSupport.buildResponse();
		response.setID("_" + UUID.randomUUID().toString());
		response.setDestination("http://localhost:8080/sample-sp/saml/sp/SSO/alias/localhost");
		response.setIssuer(buildIssuer("http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php"));
		response.getAssertions().add(assertion);
		return response;
	}

	private Assertion buildAssertion() {
		Assertion assertion = SAML2ActionTestingSupport.buildAssertion();
		assertion.setIssueInstant(DateTime.now());
		assertion.setIssuer(buildIssuer("http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php"));
		assertion.setSubject(buildSubject("testuser@spring.security.saml"));
		assertion.setConditions(buildConditions());

		SubjectConfirmation subjectConfirmation = buildSubjectConfirmation();

		// Default to bearer with basic valid confirmation data, but the test can change as appropriate
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		final SubjectConfirmationData confirmationData = buildSubjectConfirmationData(LOCAL_SP_ENTITY_ID);
		confirmationData.setRecipient("http://localhost:8080/sample-sp/saml/sp/SSO/alias/localhost");
		subjectConfirmation.setSubjectConfirmationData(confirmationData);
		assertion.getSubject().getSubjectConfirmations().add(subjectConfirmation);
		return assertion;
	}

	protected Credential getSigningCredential(String certificate, String key, UsageType usageType) throws CertificateException,
																										  KeyException {
		PublicKey publicKey = X509Support.decodeCertificate(certificate.getBytes(UTF_8)).getPublicKey();
		final PrivateKey privateKey = KeySupport.decodePrivateKey(key.getBytes(UTF_8), new char[0]);
		BasicCredential cred = CredentialSupport.getSimpleCredential(publicKey, privateKey);
		cred.setUsageType(usageType);
		cred.setEntityId("http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
		return cred;
	}

	private void signXmlObject(SignableSAMLObject object, Credential credential)
		throws MarshallingException, SecurityException, SignatureException {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		parameters.setSigningCredential(credential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		SignatureSupport.signObject(object, parameters);
	}

	private String toXml(XMLObject object) throws MarshallingException {
		final MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		Element element = marshallerFactory
			.getMarshaller(object)
			.marshall(object);
		return SerializeSupport.nodeToString(element);
	}


	private String idpCertificate = "-----BEGIN CERTIFICATE-----\n" +
		"MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYD\n" +
		"VQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYD\n" +
		"VQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwX\n" +
		"c2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0Bw\n" +
		"aXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJ\n" +
		"BgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAa\n" +
		"BgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQD\n" +
		"DBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlr\n" +
		"QHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62\n" +
		"E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz\n" +
		"2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWW\n" +
		"RDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQ\n" +
		"nX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5\n" +
		"cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gph\n" +
		"iJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5\n" +
		"ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTAD\n" +
		"AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduO\n" +
		"nRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+v\n" +
		"ZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLu\n" +
		"xbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6z\n" +
		"V9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3\n" +
		"lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk\n" +
		"-----END CERTIFICATE-----\n";

	private String idpPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4cn62E1xLqpN3\n" +
		"4PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZX\n" +
		"W+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHE\n" +
		"fDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7h\n" +
		"Z6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/T\n" +
		"Xy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7\n" +
		"I+J5lS8VAgMBAAECggEBAKyxBlIS7mcp3chvq0RF7B3PHFJMMzkwE+t3pLJcs4cZ\n" +
		"nezh/KbREfP70QjXzk/llnZCvxeIs5vRu24vbdBm79qLHqBuHp8XfHHtuo2AfoAQ\n" +
		"l4h047Xc/+TKMivnPQ0jX9qqndKDLqZDf5wnbslDmlskvF0a/MjsLU0TxtOfo+dB\n" +
		"t55FW11cGqxZwhS5Gnr+cbw3OkHz23b9gEOt9qfwPVepeysbmm9FjU+k4yVa7rAN\n" +
		"xcbzVb6Y7GCITe2tgvvEHmjB9BLmWrH3mZ3Af17YU/iN6TrpPd6Sj3QoS+2wGtAe\n" +
		"HbUs3CKJu7bIHcj4poal6Kh8519S+erJTtqQ8M0ZiEECgYEA43hLYAPaUueFkdfh\n" +
		"9K/7ClH6436CUH3VdizwUXi26fdhhV/I/ot6zLfU2mgEHU22LBECWQGtAFm8kv0P\n" +
		"zPn+qjaR3e62l5PIlSYbnkIidzoDZ2ztu4jF5LgStlTJQPteFEGgZVl5o9DaSZOq\n" +
		"Yd7G3XqXuQ1VGMW58G5FYJPtA1cCgYEAz5TPUtK+R2KXHMjUwlGY9AefQYRYmyX2\n" +
		"Tn/OFgKvY8lpAkMrhPKONq7SMYc8E9v9G7A0dIOXvW7QOYSapNhKU+np3lUafR5F\n" +
		"4ZN0bxZ9qjHbn3AMYeraKjeutHvlLtbHdIc1j3sxe/EzltRsYmiqLdEBW0p6hwWg\n" +
		"tyGhYWVyaXMCgYAfDOKtHpmEy5nOCLwNXKBWDk7DExfSyPqEgSnk1SeS1HP5ctPK\n" +
		"+1st6sIhdiVpopwFc+TwJWxqKdW18tlfT5jVv1E2DEnccw3kXilS9xAhWkfwrEvf\n" +
		"V5I74GydewFl32o+NZ8hdo9GL1I8zO1rIq/et8dSOWGuWf9BtKu/vTGTTQKBgFxU\n" +
		"VjsCnbvmsEwPUAL2hE/WrBFaKocnxXx5AFNt8lEyHtDwy4Sg1nygGcIJ4sD6koQk\n" +
		"RdClT3LkvR04TAiSY80bN/i6ZcPNGUwSaDGZEWAIOSWbkwZijZNFnSGOEgxZX/IG\n" +
		"yd39766vREEMTwEeiMNEOZQ/dmxkJm4OOVe25cLdAoGACOtPnq1Fxay80UYBf4rQ\n" +
		"+bJ9yX1ulB8WIree1hD7OHSB2lRHxrVYWrglrTvkh63Lgx+EcsTV788OsvAVfPPz\n" +
		"BZrn8SdDlQqalMxUBYEFwnsYD3cQ8yOUnijFVC4xNcdDv8OIqVgSk4KKxU5AshaA\n" +
		"xk6Mox+u8Cc2eAK12H13i+8=\n" +
		"-----END PRIVATE KEY-----\n";
}
