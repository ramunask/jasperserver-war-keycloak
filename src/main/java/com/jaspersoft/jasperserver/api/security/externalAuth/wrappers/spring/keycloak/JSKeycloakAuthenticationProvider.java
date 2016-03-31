package com.jaspersoft.jasperserver.api.security.externalAuth.wrappers.spring.keycloak;

import java.util.Collection;

import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

import com.jaspersoft.jasperserver.api.JasperServerAPI;
import com.jaspersoft.jasperserver.api.security.externalAuth.keycloak.KeycloakUserDetails;

/**
 * Jasper Server API for Keycloak authentication provider.
 * 
 * @author nico.arianto
 */
@JasperServerAPI
public class JSKeycloakAuthenticationProvider extends KeycloakAuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		final Authentication resultAuthentication = super.authenticate(authentication);
		if (resultAuthentication instanceof KeycloakAuthenticationToken) {
			final KeycloakAuthenticationToken currentAuthentication = (KeycloakAuthenticationToken) resultAuthentication;
			final OidcKeycloakAccount currentAccount = currentAuthentication.getAccount();
			final RefreshableKeycloakSecurityContext currentContext = (RefreshableKeycloakSecurityContext) currentAccount
					.getKeycloakSecurityContext();
			final Collection<GrantedAuthority> currentAuthorities = currentAuthentication.getAuthorities();
			return new KeycloakAuthenticationToken(
					new SimpleKeycloakAccount(new KeycloakUserDetails(currentAccount.getPrincipal().getName(),
							currentContext, currentAuthorities), currentAccount.getRoles(), currentContext),
					currentAuthorities);
		}
		return resultAuthentication;
	}

}
