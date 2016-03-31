package com.jaspersoft.jasperserver.api.security.externalAuth.keycloak;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import com.jaspersoft.jasperserver.api.metadata.user.domain.Role;
import com.jaspersoft.jasperserver.api.metadata.user.domain.User;

/**
 * Keycloak user details to support {@link ExternalUserSetupProcessor} or
 * <authz:authentication property="principal.fullName"/> in JasperServer.
 * 
 * @author nico.arianto
 */
public class KeycloakUserDetails extends KeycloakPrincipal<RefreshableKeycloakSecurityContext>
		implements UserDetails, User {
	private static final long serialVersionUID = 1271428277853396255L;
	private static final String password = "<secret>";
	private final Collection<GrantedAuthority> grantedAuthorities;
	private Set<?> roles = Collections.emptySet();

	public KeycloakUserDetails(String name, RefreshableKeycloakSecurityContext context,
			Collection<GrantedAuthority> grantedAuthorities) {
		super(name, context);
		this.grantedAuthorities = grantedAuthorities;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> currentGrantedAuthorities = getGrantedAuthorities();
		if (currentGrantedAuthorities == null) {
			return new ArrayList<GrantedAuthority>();
		}
		return new ArrayList<GrantedAuthority>(currentGrantedAuthorities);
	}

	public String getPassword() {
		return password;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Important: Keyclock client should have 'username' Protocol Mapper with
	 * Token Claim Name as 'preferred_username' that was add-in in ID token or
	 * access token.
	 */
	public String getUsername() {
		final RefreshableKeycloakSecurityContext context = getKeycloakSecurityContext();
		String username = context.getIdToken().getPreferredUsername();
		if (StringUtils.isEmpty(username)) {
			username = context.getToken().getPreferredUsername();
		}
		return username;
	}

	/**
	 * Returns a principal full name.<br/>
	 * <br/>
	 * Note: This method is required because of an access to spring security
	 * authentication with property as 'principal.fullName' in few JSP file.
	 * 
	 * @return token name
	 */
	public String getFullName() {
		final RefreshableKeycloakSecurityContext context = getKeycloakSecurityContext();
		String fullname = context.getIdToken().getName();
		if (StringUtils.isEmpty(fullname)) {
			fullname = context.getToken().getName();
		}
		return fullname;
	}

	/**
	 * Returns a principal email.
	 * 
	 * @return email
	 */
	public String getEmailAddress() {
		final RefreshableKeycloakSecurityContext context = getKeycloakSecurityContext();
		String email = context.getIdToken().getEmail();
		if (StringUtils.isEmpty(email)) {
			email = context.getToken().getEmail();
		}
		return email;
	}

	public boolean isAccountNonExpired() {
		return true;
	}

	public boolean isAccountNonLocked() {
		return true;
	}

	public boolean isCredentialsNonExpired() {
		return true;
	}

	public boolean isEnabled() {
		return true;
	}

	public Collection<GrantedAuthority> getGrantedAuthorities() {
		return grantedAuthorities;
	}

	public String getTenantId() {
		return null;
	}

	public void setTenantId(String arg0) {
	}

	public void addRole(Role arg0) {
	}

	@SuppressWarnings("rawtypes")
	public List getAttributes() {
		return Collections.emptyList();
	}

	public Date getPreviousPasswordChangeTime() {
		return null;
	}

	@SuppressWarnings("rawtypes")
	public Set getRoles() {
		return roles;
	}

	public boolean isExternallyDefined() {
		return true;
	}

	public void removeRole(Role arg0) {
	}

	@SuppressWarnings("rawtypes")
	public void setAttributes(List arg0) {
	}

	public void setEmailAddress(String arg0) {
	}

	public void setEnabled(boolean arg0) {
	}

	public void setExternallyDefined(boolean arg0) {
	}

	public void setFullName(String arg0) {
	}

	public void setPassword(String arg0) {
	}

	public void setPreviousPasswordChangeTime(Date arg0) {
	}

	@SuppressWarnings("rawtypes")
	public void setRoles(Set paramSet) {
		this.roles = paramSet;
	}

	public void setUsername(String arg0) {
	}

}
