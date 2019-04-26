/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml2.boot.configuration;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

import org.springframework.boot.context.properties.NestedConfigurationProperty;

import static org.springframework.security.saml2.util.Saml2StringUtils.stripSlashes;

public abstract class LocalSaml2ProviderConfiguration
	<ExternalConfiguration extends RemoteSaml2ProviderConfiguration> {

	private String entityId;
	private String alias;
	private boolean signMetadata;
	private String metadata;
	@NestedConfigurationProperty
	private Saml2RotatingKeys keys = new Saml2RotatingKeys();
	private String pathPrefix;
	private boolean singleLogoutEnabled = true;
	@NestedConfigurationProperty
	private List<String> nameIds = new LinkedList<>();
	private String defaultSigningAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	private String defaultDigest = "http://www.w3.org/2001/04/xmlenc#sha256";
	@NestedConfigurationProperty
	private List<ExternalConfiguration> providers = new LinkedList<>();
	private String basePath;


	public LocalSaml2ProviderConfiguration(String pathPrefix) {
		setPathPrefix(pathPrefix);
	}

	public String getEntityId() {
		return entityId;
	}

	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public boolean isSignMetadata() {
		return signMetadata;
	}

	public void setSignMetadata(boolean signMetadata) {
		this.signMetadata = signMetadata;
	}

	public String getMetadata() {
		return metadata;
	}

	public void setMetadata(String metadata) {
		this.metadata = metadata;
	}

	public Saml2RotatingKeys getKeys() {
		return keys;
	}

	public void setKeys(Saml2RotatingKeys keys) {
		this.keys = keys;
	}

	public String getPathPrefix() {
		return pathPrefix;
	}

	public void setPathPrefix(String pathPrefix) {
		this.pathPrefix = stripSlashes(pathPrefix);
	}

	public boolean isSingleLogoutEnabled() {
		return singleLogoutEnabled;
	}

	public void setSingleLogoutEnabled(boolean singleLogoutEnabled) {
		this.singleLogoutEnabled = singleLogoutEnabled;
	}

	public List<String> getNameIds() {
		return nameIds;
	}

	public void setNameIds(List<String> nameIds) {
		this.nameIds = new LinkedList<>(new HashSet<>(nameIds));
	}

	public String getDefaultSigningAlgorithm() {
		return defaultSigningAlgorithm;
	}

	public void setDefaultSigningAlgorithm(String defaultSigningAlgorithm) {
		this.defaultSigningAlgorithm = defaultSigningAlgorithm;
	}

	public String getDefaultDigest() {
		return defaultDigest;
	}

	public void setDefaultDigest(String defaultDigest) {
		this.defaultDigest = defaultDigest;
	}

	public List<ExternalConfiguration> getProviders() {
		return providers;
	}

	public void setProviders(List<ExternalConfiguration> providers) {
		this.providers = providers;
	}

	public String getBasePath() {
		return basePath;
	}

	public void setBasePath(String basePath) {
		this.basePath = basePath;
	}
}
