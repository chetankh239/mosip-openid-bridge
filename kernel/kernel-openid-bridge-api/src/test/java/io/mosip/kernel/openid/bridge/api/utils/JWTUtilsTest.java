package io.mosip.kernel.openid.bridge.api.utils;

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
		token = JWT.create().withSubject("mock-user").withClaim("present", "value").withNullClaim("nullClaim")
				.sign(Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate()));
	}

	@Test
	public void getVerificationAlgorithmWithUnknownAlgorithmThenFallbackToRS256Test() {
		DecodedJWT decodedJWT = JWT.decode(token);

		JWTUtils.getVerificationAlgorithm("unknown", keyPair.getPublic()).verify(decodedJWT);
	}

	@Test
	public void getVerificationAlgorithmWithNullAlgorithmThenFallbackToRS256Test() {
		DecodedJWT decodedJWT = JWT.decode(token);

		JWTUtils.getVerificationAlgorithm(null, keyPair.getPublic()).verify(decodedJWT);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithmWithFallbackAndTokenSignedByOtherAlgorithmThenFailTest() {
		String ps256Token = JWT.create().withSubject("mock-user").sign(
				Algorithm.RSA256PSS((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate()));

		JWTUtils.getVerificationAlgorithm("unknown", keyPair.getPublic()).verify(JWT.decode(ps256Token));
	}

	@Test
	public void isClaimPresentWithValueThenTrueTest() {
		assertTrue(JWTUtils.isClaimPresent(JWT.decode(token).getClaim("present")));
	}

	@Test
	public void isClaimPresentWithMissingClaimThenFalseTest() {
		assertFalse(JWTUtils.isClaimPresent(JWT.decode(token).getClaim("absent")));
	}

	@Test
	public void isClaimPresentWithJsonNullClaimThenFalseTest() {
		assertFalse(JWTUtils.isClaimPresent(JWT.decode(token).getClaim("nullClaim")));
	}

	@Test
	public void isClaimPresentWithNullClaimThenFalseTest() {
		assertFalse(JWTUtils.isClaimPresent(null));
	}
}
