package com.example.authorizationserver.config.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	/**
	 * 프로토콜 엔드포인트를 위한 Spring Security filter chain
	 * @param http
	 * @return SecurityFilterChain
	 * @throws Exception
	 */
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());	// OpenID Connect 1.0 사용

		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer((resourceServer) -> resourceServer
				.jwt(Customizer.withDefaults()));

		return http.build();
	}

	/**
	 * 인증을 위한 Spring Security filter chain
	 * @param http
	 * @return SecurityFilterChain
	 * @throws Exception
	 */
	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http.csrf(AbstractHttpConfigurer::disable);
		http
			.authorizeHttpRequests(authorize -> {
				authorize
					.requestMatchers("/**").permitAll()
					.requestMatchers(PathRequest.toH2Console()).permitAll()
					.anyRequest().authenticated();
				}
			)
			.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.formLogin(Customizer.withDefaults());

		return http.build();
	}

	/**
	 * 인증할 사용자를 검색하기 위한 UserDetailsService 인스턴스
	 * @return InMemoryUserDetailsManager
	 */
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails userDetails = User
			.withUsername("user")
			.passwordEncoder(passwordEncoder()::encode)
			// .password(passwordEncoder().encode("password"))
			.password("1234")
			.roles("USER")
			.build();

		return new InMemoryUserDetailsManager(userDetails);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * 클라이언트를 관리하기 위한 등록 역할의 Client Repository
	 * @return InMemoryRegisteredClientRepository
	 */
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient customClient = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientName("custom")
			.clientId("custom-client-id")
			.clientSecret(passwordEncoder().encode("custom-client-secret"))
			.clientAuthenticationMethods(methods -> {
				methods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
			})
			.authorizationGrantTypes(types -> {
				types.add(AuthorizationGrantType.AUTHORIZATION_CODE);
				types.add(AuthorizationGrantType.REFRESH_TOKEN);
			})
			.redirectUris(uris -> {
				uris.add("http://localhost:3000");
			})
			.postLogoutRedirectUris(uris -> {
				uris.add("http://localhost:3000");
			})
			.scopes(scopes -> {
				scopes.add(OidcScopes.OPENID);
				scopes.add(OidcScopes.PROFILE);
			})
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();

		return new InMemoryRegisteredClientRepository(customClient);
	}

	/**
	 * 액세스 토큰 서명을 위한 com.nimbusds.jose.jwk.source.JWKSource 인스턴스
	 * 실제 운영시에는 pem key 를 keyStore에 저장하고 주입 받아야 함
	 * @return ImmutableJWKSet
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	/**
	 * 시작 시 생성된 키가 있는 java.security.KeyPair 인스턴스로 위의 JWKSource 만드는 데 사용
	 * @return KeyPair
	 */
	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	/**
	 * 서명된 액세스 토큰을 디코딩하기 위한 JwtDecoder
	 * 토큰 검증에 필요
	 * @param jwkSource
	 * @return OAuth2AuthorizationServerConfiguration
	 */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/**
	 * 	Spring Authorization Server 구성을 위한 AuthorizationServerSettings
	 * 	여러 EndPoint 설정함
	 * @return AuthorizationServerSettings
	 */
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
			.build();
	}

	/* SQL 실행문 */
	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
			.generateUniqueName(true)
			.setType(EmbeddedDatabaseType.H2)
			.setScriptEncoding("UTF-8")
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
			.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
			.build();
		// @formatter:on
	}
}