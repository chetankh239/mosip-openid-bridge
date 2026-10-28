package io.mosip.kernel.openid.bridge.api.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.BeforeClass;
import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JWTUtilsTest {

	private static KeyPair keyPair;
	private static String token;

	@BeforeClass
	public static void init() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		keyPair = generator.generateKeyPair();
		token = JWT.create().withIssuer("https://iam.mosip.net/auth/realms/mosip").withSubject("mock-user")
				.withClaim("present", "value").withNullClaim("nullClaim")
				.sign(Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate()));
	}

	@Test
	public void getVerificationAlgorithm_withUnknownAlgorithm_thenFallbackToRS256() {
		DecodedJWT decodedJWT = JWT.decode(token);

		JWTUtils.getVerificationAlgorithm("EdDSA", keyPair.getPublic()).verify(decodedJWT);
	}

	@Test
	public void getVerificationAlgorithm_withNullAlgorithm_thenFallbackToRS256() {
		DecodedJWT decodedJWT = JWT.decode(token);

		JWTUtils.getVerificationAlgorithm(null, keyPair.getPublic()).verify(decodedJWT);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithm_withFallbackAndTokenSignedByOtherAlgorithm_thenFail() {
		String ps256Token = JWT.create().withSubject("mock-user").sign(
				Algorithm.RSA256PSS((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate()));

		JWTUtils.getVerificationAlgorithm("unknown", keyPair.getPublic()).verify(JWT.decode(ps256Token));
	}

	@Test
	public void isClaimPresent_withValue_thenTrue() {
		assertTrue(JWTUtils.isClaimPresent(JWT.decode(token).getClaim("present")));
	}

	@Test
	public void isClaimPresent_withMissingClaim_thenFalse() {
		assertFalse(JWTUtils.isClaimPresent(JWT.decode(token).getClaim("absent")));
	}

	@Test
	public void isClaimPresent_withJsonNullClaim_thenFalse() {
		assertFalse(JWTUtils.isClaimPresent(JWT.decode(token).getClaim("nullClaim")));
	}

	@Test
	public void isClaimPresent_withNullClaim_thenFalse() {
		assertFalse(JWTUtils.isClaimPresent(null));
	}

	@Test
	public void getissuer_thenReturnIssuerFromToken() {
		assertEquals("https://iam.mosip.net/auth/realms/mosip", JWTUtils.getissuer(token));
		// second call is served from the cache
		assertEquals("https://iam.mosip.net/auth/realms/mosip", JWTUtils.getissuer(token));
	}

	@Test
	public void getSubClaimValueFromToken_thenReturnClaimValue() {
		assertEquals("value", JWTUtils.getSubClaimValueFromToken(token, "present"));
	}
}
