package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenRevocationEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedList;
import java.util.List;

public class OAuth2TokenRevocationEndpointConfigurer extends AbstractOAuth2Configurer{
	private AuthenticationConverter authenticationConverter;
	private final List<AuthenticationProvider> authenticationProviders = new LinkedList<>();

	private AuthenticationSuccessHandler tokenRevocationSuccessHandler;
	private AuthenticationFailureHandler tokenRevocationFailureHandler;
	private RequestMatcher requestMatcher;

	public OAuth2TokenRevocationEndpointConfigurer authenticationConverter(AuthenticationConverter authenticationConverter){
		this.authenticationConverter = authenticationConverter;
		return this;
	}
	public OAuth2TokenRevocationEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}
	OAuth2TokenRevocationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	public OAuth2TokenRevocationEndpointConfigurer onAuthenticationSuccess(AuthenticationSuccessHandler tokenRevocationSuccessHandler){
		this.tokenRevocationSuccessHandler = tokenRevocationSuccessHandler;
		return this;
	}

	public OAuth2TokenRevocationEndpointConfigurer onAuthenticationFailure(AuthenticationFailureHandler tokenRevocationFailureHandler){
		this.tokenRevocationFailureHandler = tokenRevocationFailureHandler;
		return this;
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void init(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		this.requestMatcher = new AntPathRequestMatcher(
				providerSettings.getTokenRevocationEndpoint(), HttpMethod.POST.name());

		List<AuthenticationProvider> authenticationProviders =
				!this.authenticationProviders.isEmpty() ?
						this.authenticationProviders :
						OAuth2ConfigurerUtils.createDefaultAuthenticationProviders(builder);
		authenticationProviders.forEach(authenticationProvider ->
				builder.authenticationProvider(postProcess(authenticationProvider)));
	}


	@Override
	<B extends HttpSecurityBuilder<B>> void configure(B builder) {
		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);

		OAuth2TokenRevocationEndpointFilter endpointFilter =
				new OAuth2TokenRevocationEndpointFilter(
						authenticationManager,
						providerSettings.getTokenRevocationEndpoint()
				);

		if (this.authenticationConverter != null) {
			endpointFilter.setAuthenticationConverter(this.authenticationConverter);
		}
		if (this.tokenRevocationSuccessHandler != null) {
			endpointFilter.setAuthenticationSuccessHandler(this.tokenRevocationSuccessHandler);
		}
		if (this.tokenRevocationFailureHandler != null) {
			endpointFilter.setAuthenticationFailureHandler(this.tokenRevocationFailureHandler);
		}
		builder.addFilterAfter(postProcess(endpointFilter), FilterSecurityInterceptor.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}
}
