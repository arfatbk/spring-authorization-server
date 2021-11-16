package org.springframework.security.oauth2.server.authorization.web.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

public class DefaultTokenRevocationAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// token (REQUIRED)
		String token = parameters.getFirst(OAuth2ParameterNames.TOKEN);
		if (!StringUtils.hasText(token) ||
				parameters.get(OAuth2ParameterNames.TOKEN).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.TOKEN);
		}

		// token_type_hint (OPTIONAL)
		String tokenTypeHint = parameters.getFirst(OAuth2ParameterNames.TOKEN_TYPE_HINT);
		if (StringUtils.hasText(tokenTypeHint) &&
				parameters.get(OAuth2ParameterNames.TOKEN_TYPE_HINT).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.TOKEN_TYPE_HINT);
		}

		return new OAuth2TokenRevocationAuthenticationToken(token, clientPrincipal, tokenTypeHint);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Token Revocation Parameter: " + parameterName,
				"https://tools.ietf.org/html/rfc7009#section-2.1");
		throw new OAuth2AuthenticationException(error);
	}
}
