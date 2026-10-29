package io.mosip.kernel.openid.bridge.api.utils;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import org.junit.BeforeClass;
import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JWTUtilsHmacTest {

	private static final String HS384_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";
	private static final String HS512_SECRET = HS384_SECRET + "0123456789abcdef";

	private static KeyPair rsaKeyPair;

	@BeforeClass
	public static void init() throws Exception {
		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(2048);
		rsaKeyPair = rsa.generateKeyPair();
	}

	@Test
	public void isHmacTokenWithHS384AndHS512TokensThenTrueTest() {
		assertTrue(JWTUtils.isHmacToken(JWT.decode(hs384(HS384_SECRET, "mock-user"))));
		assertTrue(JWTUtils.isHmacToken(JWT.decode(hs512(HS512_SECRET, "mock-user"))));
	}

	@Test
	public void isHmacTokenWithOtherAlgorithmsThenFalseTest() {
		String hs256 = JWT.create().withSubject("mock-user").sign(Algorithm.HMAC256(HS384_SECRET));
		String rs256 = JWT.create().withSubject("mock-user").sign(
				Algorithm.RSA256((RSAPublicKey) rsaKeyPair.getPublic(), (RSAPrivateKey) rsaKeyPair.getPrivate()));

		assertFalse(JWTUtils.isHmacToken(JWT.decode(hs256)));
		assertFalse(JWTUtils.isHmacToken(JWT.decode(rs256)));
	}

	@Test
	public void isHmacSignatureValidWithHS384ThenTrueTest() {
		assertTrue(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")), HS384_SECRET));
	}

	@Test
	public void isHmacSignatureValidWithHS512ThenTrueTest() {
		assertTrue(JWTUtils.isHmacSignatureValid(JWT.decode(hs512(HS512_SECRET, "mock-user")), HS512_SECRET));
	}

	@Test
	public void isHmacSignatureValidWithWrongSecretThenFalseTest() {
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")),
				HS384_SECRET.replace('0', '9')));
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs512(HS512_SECRET, "mock-user")),
				HS512_SECRET.replace('0', '9')));
	}

	@Test
	public void isHmacSignatureValidWithTamperedPayloadThenFalseTest() {
		String[] original = hs512(HS512_SECRET, "mock-user").split("\\.");
		String[] other = hs512(HS512_SECRET, "other-user").split("\\.");

		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(original[0] + "." + other[1] + "." + original[2]),
				HS512_SECRET));
	}

	@Test
	public void isHmacSignatureValidWithoutConfiguredSecretThenFalseTest() {
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")), null));
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")), ""));
	}

	@Test
	public void isHmacSignatureValidWithSecretShorterThanHashOutputThenFalseTest() {
		String shortHs384Secret = HS384_SECRET.substring(0, 47);
		String shortHs512Secret = HS512_SECRET.substring(0, 63);

		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(shortHs384Secret, "mock-user")), shortHs384Secret));
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs512(shortHs512Secret, "mock-user")), shortHs512Secret));
	}

	@Test
	public void isHmacSignatureValidWithSecretExactlyAsLongAsHashOutputThenTrueTest() {
		assertTrue(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")), HS384_SECRET));
		assertTrue(JWTUtils.isHmacSignatureValid(JWT.decode(hs512(HS512_SECRET, "mock-user")), HS512_SECRET));
	}

	@Test
	public void isHmacSignatureValidWithTokenOfOtherAlgorithmThenFalseTest() {
		String hs256 = JWT.create().withSubject("mock-user").sign(Algorithm.HMAC256(HS384_SECRET));

		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs256), HS384_SECRET));
	}

	@Test
	public void isHmacSignatureValidWithTokenSignedWithPublicKeyAsSecretThenFalseTest() {
		byte[] publicKeyBytes = Base64.getEncoder().encode(rsaKeyPair.getPublic().getEncoded());
		String forged = JWT.create().withSubject("admin").sign(Algorithm.HMAC512(publicKeyBytes));

		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(forged), HS512_SECRET));
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(forged), null));
	}

	private String hs384(String secret, String subject) {
		return JWT.create().withSubject(subject).sign(Algorithm.HMAC384(secret.getBytes(StandardCharsets.UTF_8)));
	}

	private String hs512(String secret, String subject) {
		return JWT.create().withSubject(subject).sign(Algorithm.HMAC512(secret.getBytes(StandardCharsets.UTF_8)));
	}
}
