/**
 * 
 */
package com.jaspersoft.jasperserver.api.security.externalAuth.processors.keycloak;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import com.jaspersoft.jasperserver.api.JSException;
import com.jaspersoft.jasperserver.api.metadata.user.domain.Role;
import com.jaspersoft.jasperserver.api.metadata.user.domain.User;
import com.jaspersoft.jasperserver.api.metadata.user.domain.impl.client.MetadataUserDetails;
import com.jaspersoft.jasperserver.api.security.externalAuth.keycloak.KeycloakUserDetails;
import com.jaspersoft.jasperserver.api.security.externalAuth.processors.ExternalUserSetupProcessor;
import com.jaspersoft.jasperserver.api.security.externalAuth.processors.ProcessorData;

/**
 * Keycloak user setup processor.
 * 
 * @author nico.arianto
 */
public class KeycloakUserSetupProcessor extends ExternalUserSetupProcessor {
	private static final Logger logger = LogManager.getLogger(KeycloakUserSetupProcessor.class);

	/**
	 * Update the authentication object in {@link SecurityContextHolder} where
	 * the authorities attribute was been merged with JasperServer user roles.
	 * <br/>
	 * <br/>
	 * Important: Replica a code from {@link UserAuthorityServiceImpl} to
	 * generate {@link UsernamePasswordAuthenticationToken}.
	 * 
	 * @param user
	 *            user
	 */
	private void updateAuthentication(User user) {
		final MetadataUserDetails userDetails = new MetadataUserDetails(user);
		if (!userDetails.getAuthorities().isEmpty()) {
			final Authentication authentication;
			final UserDetails externalUserDetails = (UserDetails) ProcessorData.getInstance()
					.getData(ProcessorData.Key.EXTERNAL_AUTH_DETAILS);
			if (externalUserDetails instanceof KeycloakUserDetails) {
				final KeycloakUserDetails principal = (KeycloakUserDetails) externalUserDetails;
				principal.setRoles(userDetails.getRoles());
				authentication = new KeycloakAuthenticationToken(new SimpleKeycloakAccount(principal,
						Collections.<String> emptySet(), principal.getKeycloakSecurityContext()),
						userDetails.getAuthorities());
			} else {
				authentication = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(),
						userDetails.getAuthorities());
			}
			if (logger.isDebugEnabled()) {
				logger.debug("Setting Authentication to: " + authentication);
			}
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} else {
			SecurityContextHolder.getContext().setAuthentication(null);
		}
	}

	/**
	 * Disabled few functions from the original process() in
	 * {@link ExternalUserSetupProcessor}.<br/>
	 * <br/>
	 * Here's the functions that been disabled:<br/>
	 * - Disabled user.isExternallyDefined() validation<br/>
	 * - Disabled getUserAuthorityService().makeUserLoggedIn(user).
	 */
	@Override
	public void process() {
		ProcessorData processorData = ProcessorData.getInstance();
		UserDetails userDetails = (UserDetails) processorData.getData(ProcessorData.Key.EXTERNAL_AUTH_DETAILS);
		try {
			String userName = userDetails.getUsername();
			if (logger.isDebugEnabled()) {
				logger.debug("Setting up external user: " + userName);
			}
			User user = getUser();
			if (user == null) {
				user = createNewExternalUser(userName);
			} else {
				if (!user.isEnabled()) {
					throw new JSException("External user " + user.getUsername()
							+ " was disabled on jasperserver. Please contact an admin user to re-enable.");
				}
			}
			@SuppressWarnings("unchecked")
			List<GrantedAuthority> grantedAuthorities = (List<GrantedAuthority>) processorData
					.getData(ProcessorData.Key.EXTERNAL_AUTHORITIES);
			String tenantId = (String) processorData.getData(ProcessorData.Key.EXTERNAL_JRS_USER_TENANT_ID);
			Set<Role> externalRoles = convertGrantedAuthoritiesToRoles(grantedAuthorities, tenantId);
			user.setTenantId(tenantId);
			try {
				alignInternalAndExternalUser(externalRoles, user);
			} catch (KeycloakAuthenticationException authenticationException) {
				logger.warn(authenticationException.getMessage());
			}
			updateAuthentication(user);
		} catch (RuntimeException exception) {
			String userName = userDetails != null ? userDetails.getUsername() : "";
			logger.error("Error processing external user " + userName + ": " + exception.getMessage());
			throw exception;
		}
	}

	@Override
	protected void alignInternalAndExternalUser(@SuppressWarnings("rawtypes") Set remoteExternalUserRoles, User user) {
		super.alignInternalAndExternalUser(remoteExternalUserRoles, user);
		if (logger.isDebugEnabled()) {
			logger.debug("External user " + user.getUsername() + " has been synchronized.");
		}
	}

	@Override
	protected void updateUserAttributes(User user) {
		super.updateUserAttributes(user);
		if (user.isExternallyDefined()) {
			throw new KeycloakAuthenticationException(
					"Internally defined user " + user.getUsername() + " already exists.");
		}
		UserDetails userDetails = (UserDetails) ProcessorData.getInstance()
				.getData(ProcessorData.Key.EXTERNAL_AUTH_DETAILS);
		if (userDetails instanceof KeycloakUserDetails) {
			KeycloakUserDetails currentUserDetails = (KeycloakUserDetails) userDetails;
			user.setFullName(currentUserDetails.getFullName());
			user.setEmailAddress(currentUserDetails.getEmailAddress());
		}
	}

}
