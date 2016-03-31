package com.jaspersoft.jasperserver.api.security.externalAuth.adapters.keycloak;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.FileSystemNotFoundException;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.HttpFacade.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Keycloak configuration resolver.
 * 
 * @author nico.arianto
 */
public class JSKeycloakConfigResolver implements KeycloakConfigResolver, InitializingBean {
	private static final Logger log = LoggerFactory.getLogger(JSKeycloakConfigResolver.class);
	private final String realmCookieName;
	private final Map<String, Resource> keycloakConfigFileResources;
	private final Map<String, KeycloakDeployment> keycloakDeploymentCache = new HashMap<String, KeycloakDeployment>();

	/**
	 * Constructor.
	 * 
	 * @param realmCookieName
	 *            realm cookie name
	 * @param keycloakConfigFileResources
	 *            Keycloak configuration file resources
	 */
	public JSKeycloakConfigResolver(String realmCookieName, Map<String, Resource> keycloakConfigFileResources) {
		this.realmCookieName = realmCookieName;
		this.keycloakConfigFileResources = keycloakConfigFileResources;
	}

	/**
	 * Resolve a deployment based on the query parameter name as a realm name.
	 * 
	 * @return Keycloak deployment
	 */
	public KeycloakDeployment resolve(Request facade) {
		final HttpFacade.Cookie cookie = facade.getCookie(realmCookieName);
		String realmName = cookie == null ? null : cookie.getValue();
		Resource resource = null;
		if (StringUtils.isEmpty(realmName) && !CollectionUtils.isEmpty(keycloakConfigFileResources)) {
			log.warn("No realm name been passed, it will use the first entry inside the map!");
			final Map.Entry<String, Resource> entry = keycloakConfigFileResources.entrySet().iterator().next();
			realmName = entry.getKey();
			resource = entry.getValue();
		} else {
			resource = keycloakConfigFileResources.get(realmName);
		}
		try {
			if (resource == null) {
				throw new FileNotFoundException(
						"Unable to find a Keycloak configuration file with realm name: " + realmName);
			}
			KeycloakDeployment deployment = keycloakDeploymentCache.get(realmName);
			if (deployment == null) {
				if (!resource.isReadable()) {
					throw new FileNotFoundException(
							"Unable to locate Keycloak configuration file: " + resource.getFilename());
				}
				deployment = KeycloakDeploymentBuilder.build(resource.getInputStream());
				keycloakDeploymentCache.put(realmName, deployment);
			}
			return deployment;
		} catch (IOException exception) {
			throw new FileSystemNotFoundException(exception.getMessage());
		}
	}

	/**
	 * Validate a query parameter name and Keycloak configuration file
	 * resources.
	 * 
	 * @throws Exception
	 *             exception
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(realmCookieName);
		Assert.notEmpty(keycloakConfigFileResources);
	}

}
