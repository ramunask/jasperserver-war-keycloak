package com.jaspersoft.jasperserver.api.security.externalAuth.filters.keycloak;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.web.util.CookieGenerator;

/**
 * Keycloak configuration resolver.<br/>
 * <br/>
 * Important: This extended filter will store the selected realm to cookie that
 * will be used in {@link JSKeycloakConfigResolver}.
 * 
 * @author nico.arianto
 */
public class JSKeycloakPreAuthActionsFilter extends KeycloakPreAuthActionsFilter implements InitializingBean {
	private final String realmQueryParamName;
	private final String realmCookieName;
	private final CookieGenerator cookieGenerator;

	/**
	 * Constructor.
	 * 
	 * @param realmQueryParamName
	 *            realm query parameter name
	 * @param realmCookieName
	 *            realm cookie name
	 */
	public JSKeycloakPreAuthActionsFilter(String realmQueryParamName, String realmCookieName) {
		super();
		this.realmQueryParamName = realmQueryParamName;
		this.realmCookieName = realmCookieName;
		this.cookieGenerator = new CookieGenerator();
		cookieGenerator.setCookieName(realmCookieName);
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		final String realmName = request.getParameter(realmQueryParamName);
		if (StringUtils.isNotEmpty(realmName) && (response instanceof HttpServletResponse)) {
			cookieGenerator.addCookie((HttpServletResponse) response, realmName);
		}
		super.doFilter(request, response, chain);
	}

	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();
		Assert.notNull(realmQueryParamName);
		Assert.notNull(realmCookieName);
	}

}
