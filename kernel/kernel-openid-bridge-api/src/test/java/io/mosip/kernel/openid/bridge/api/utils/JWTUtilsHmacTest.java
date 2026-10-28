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

/**
 * Verifies HS384 and HS512 signature checking with a configured shared secret.
 */
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
	public void isHmacToken_withHS384AndHS512Tokens_thenTrue() {
		assertTrue(JWTUtils.isHmacToken(JWT.decode(hs384(HS384_SECRET, "mock-user"))));
		assertTrue(JWTUtils.isHmacToken(JWT.decode(hs512(HS512_SECRET, "mock-user"))));
	}

	@Test
	public void isHmacToken_withOtherAlgorithms_thenFalse() {
		String hs256 = JWT.create().withSubject("mock-user").sign(Algorithm.HMAC256(HS384_SECRET));
		String rs256 = JWT.create().withSubject("mock-user").sign(
				Algorithm.RSA256((RSAPublicKey) rsaKeyPair.getPublic(), (RSAPrivateKey) rsaKeyPair.getPrivate()));

		assertFalse(JWTUtils.isHmacToken(JWT.decode(hs256)));
		assertFalse(JWTUtils.isHmacToken(JWT.decode(rs256)));
	}

	@Test
	public void isHmacSignatureValid_withHS384_thenTrue() {
		assertTrue(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")), HS384_SECRET));
	}

	@Test
	public void isHmacSignatureValid_withHS512_thenTrue() {
		assertTrue(JWTUtils.isHmacSignatureValid(JWT.decode(hs512(HS512_SECRET, "mock-user")), HS512_SECRET));
	}

	@Test
	public void isHmacSignatureValid_withWrongSecret_thenFalse() {
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")),
				HS384_SECRET.replace('0', '9')));
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs512(HS512_SECRET, "mock-user")),
				HS512_SECRET.replace('0', '9')));
	}

	@Test
	public void isHmacSignatureValid_withTamperedPayload_thenFalse() {
		String[] original = hs512(HS512_SECRET, "mock-user").split("\\.");
		String[] other = hs512(HS512_SECRET, "other-user").split("\\.");

		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(original[0] + "." + other[1] + "." + original[2]),
				HS512_SECRET));
	}

	@Test
	public void isHmacSignatureValid_withoutConfiguredSecret_thenFalse() {
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")), null));
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")), ""));
	}

	@Test
	public void isHmacSignatureValid_withSecretShorterThanHashOutput_thenFalse() {
		String shortHs384Secret = HS384_SECRET.substring(0, 47);
		String shortHs512Secret = HS512_SECRET.substring(0, 63);

		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(shortHs384Secret, "mock-user")), shortHs384Secret));
		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs512(shortHs512Secret, "mock-user")), shortHs512Secret));
	}

	@Test
	public void isHmacSignatureValid_withSecretExactlyAsLongAsHashOutput_thenTrue() {
		assertTrue(JWTUtils.isHmacSignatureValid(JWT.decode(hs384(HS384_SECRET, "mock-user")), HS384_SECRET));
		assertTrue(JWTUtils.isHmacSignatureValid(JWT.decode(hs512(HS512_SECRET, "mock-user")), HS512_SECRET));
	}

	@Test
	public void isHmacSignatureValid_withTokenOfOtherAlgorithm_thenFalse() {
		String hs256 = JWT.create().withSubject("mock-user").sign(Algorithm.HMAC256(HS384_SECRET));

		assertFalse(JWTUtils.isHmacSignatureValid(JWT.decode(hs256), HS384_SECRET));
	}

	@Test
	public void isHmacSignatureValid_withTokenSignedWithPublicKeyAsSecret_thenFalse() {
		// algorithm confusion: the attacker uses a public key as the HMAC secret
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
