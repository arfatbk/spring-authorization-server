package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenRevocationEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class OAuth2TokenRevocationEndpointConfigurer extends AbstractOAuth2Configurer{
	private AuthenticationSuccessHandler tokenRevocationSuccessHandler;
	private AuthenticationFailureHandler tokenRevocationFailureHandler;
	private RequestMatcher requestMatcher;

	OAuth2TokenRevocationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	public OAuth2TokenRevocationEndpointConfigurer tokenRevocationSuccessHandler(AuthenticationSuccessHandler tokenRevocationSuccessHandler){
		this.tokenRevocationSuccessHandler = tokenRevocationSuccessHandler;
		return this;
	}

	public OAuth2TokenRevocationEndpointConfigurer tokenRevocationFailureHandler(AuthenticationFailureHandler tokenRevocationFailureHandler){
		this.tokenRevocationFailureHandler = tokenRevocationFailureHandler;
		return this;
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void init(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		this.requestMatcher = new AntPathRequestMatcher(
				providerSettings.getTokenRevocationEndpoint(), HttpMethod.POST.name());
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void configure(B builder) {
		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);

		OAuth2TokenRevocationEndpointFilter oAuth2TokenRevocationEndpointFilter =
				new OAuth2TokenRevocationEndpointFilter(
						authenticationManager,
						providerSettings.getTokenRevocationEndpoint()
				);

		if (this.tokenRevocationSuccessHandler != null) {
			oAuth2TokenRevocationEndpointFilter.setAuthenticationSuccessHandler(this.tokenRevocationSuccessHandler);
		}
		if (this.tokenRevocationFailureHandler != null) {
			oAuth2TokenRevocationEndpointFilter.setAuthenticationFailureHandler(this.tokenRevocationFailureHandler);
		}
		builder.addFilterAfter(postProcess(oAuth2TokenRevocationEndpointFilter), FilterSecurityInterceptor.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}
}
