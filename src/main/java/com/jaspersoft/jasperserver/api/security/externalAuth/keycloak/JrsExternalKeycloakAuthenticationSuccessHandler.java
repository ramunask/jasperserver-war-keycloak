package com.jaspersoft.jasperserver.api.security.externalAuth.keycloak;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import com.jaspersoft.jasperserver.api.security.JrsAuthenticationSuccessHandler;
import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalDataSynchronizer;

/**
 * A replica of {@link JrsExternalCASAuthenticationSuccessHandler} to support
 * SSO Authentication synchronization of {@link ExternalDataSynchronizer}.
 * 
 * @author nico.arianto
 */
public class JrsExternalKeycloakAuthenticationSuccessHandler extends JrsAuthenticationSuccessHandler
		implements InitializingBean {
	private ExternalDataSynchronizer externalDataSynchronizer;

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.externalDataSynchronizer, "externalDataSynchronizer cannot be null");
	}

	/**
	 * On successful authentication,if authentication is instance of
	 * {@link KeycloakAuthenticationToken}, this method will set the
	 * authentication and synchronize the authentication object with help of
	 * {@link ExternalDataSynchronizer}.
	 */
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws ServletException, IOException {
		try {
			if ((authentication instanceof KeycloakAuthenticationToken)) {
				SecurityContextHolder.getContext().setAuthentication(authentication);
				this.externalDataSynchronizer.synchronize();
			}
			super.onAuthenticationSuccess(request, response, authentication);
		} catch (RuntimeException exception) {
			SecurityContextHolder.getContext().setAuthentication(null);
			throw exception;
		}
	}

	protected ExternalDataSynchronizer getExternalDataSynchronizer() {
		return externalDataSynchronizer;
	}

	public void setExternalDataSynchronizer(ExternalDataSynchronizer externalDataSynchronizer) {
		this.externalDataSynchronizer = externalDataSynchronizer;
	}

}
