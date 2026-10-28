package io.mosip.kernel.openid.bridge.api.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

@RunWith(Parameterized.class)
public class JWTUtilsVerificationAlgorithmTest {

	private static final Map<String, KeyPair[]> KEY_PAIRS = new HashMap<>();

	private final String tokenAlgo;

	public JWTUtilsVerificationAlgorithmTest(String tokenAlgo) {
		this.tokenAlgo = tokenAlgo;
	}

	@Parameters(name = "{0}")
	public static Collection<String> algorithms() {
		return Arrays.asList("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512");
	}

	@BeforeClass
	public static void generateKeys() throws Exception {
		for (String algo : algorithms()) {
			KEY_PAIRS.put(algo, new KeyPair[] { generateKeyPair(algo), generateKeyPair(algo) });
		}
	}

	@Test
	public void getVerificationAlgorithm_withValidSignature_thenPass() throws Exception {
		KeyPair keyPair = signingKeyPair();
		DecodedJWT token = JWT.decode(sign(keyPair, "mock-user"));

		JWTUtils.getVerificationAlgorithm(tokenAlgo, keyPair.getPublic()).verify(token);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithm_withWrongKey_thenFail() throws Exception {
		DecodedJWT token = JWT.decode(sign(signingKeyPair(), "mock-user"));

		JWTUtils.getVerificationAlgorithm(tokenAlgo, KEY_PAIRS.get(tokenAlgo)[1].getPublic()).verify(token);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithm_withTamperedPayload_thenFail() throws Exception {
		KeyPair keyPair = signingKeyPair();
		String[] original = sign(keyPair, "mock-user").split("\\.");
		String[] other = sign(keyPair, "other-user").split("\\.");
		DecodedJWT tampered = JWT.decode(original[0] + "." + other[1] + "." + original[2]);

		JWTUtils.getVerificationAlgorithm(tokenAlgo, keyPair.getPublic()).verify(tampered);
	}

	@Test(expected = AlgorithmMismatchException.class)
	public void getVerificationAlgorithm_withKeyOfOtherType_thenFail() throws Exception {
		String otherKeyAlgo = tokenAlgo.startsWith("ES") ? "RS256" : "ES256";

		JWTUtils.getVerificationAlgorithm(tokenAlgo, KEY_PAIRS.get(otherKeyAlgo)[0].getPublic());
	}

	private KeyPair signingKeyPair() {
		return KEY_PAIRS.get(tokenAlgo)[0];
	}

	private String sign(KeyPair keyPair, String subject) {
		return JWT.create().withSubject(subject).withIssuedAt(Date.from(Instant.now()))
				.withExpiresAt(Date.from(Instant.now().plusSeconds(300))).sign(signingAlgorithm(keyPair));
	}

	private Algorithm signingAlgorithm(KeyPair keyPair) {
		if (tokenAlgo.startsWith("ES")) {
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
			return switch (tokenAlgo) {
			case "ES384" -> Algorithm.ECDSA384(publicKey, privateKey);
			case "ES512" -> Algorithm.ECDSA512(publicKey, privateKey);
			default -> Algorithm.ECDSA256(publicKey, privateKey);
			};
		}
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return switch (tokenAlgo) {
		case "RS384" -> Algorithm.RSA384(publicKey, privateKey);
		case "RS512" -> Algorithm.RSA512(publicKey, privateKey);
		case "PS256" -> Algorithm.RSA256PSS(publicKey, privateKey);
		case "PS384" -> Algorithm.RSA384PSS(publicKey, privateKey);
		case "PS512" -> Algorithm.RSA512PSS(publicKey, privateKey);
		default -> Algorithm.RSA256(publicKey, privateKey);
		};
	}

	private static KeyPair generateKeyPair(String tokenAlgo) throws Exception {
		if (tokenAlgo.startsWith("ES")) {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec(switch (tokenAlgo) {
			case "ES384" -> "secp384r1";
			case "ES512" -> "secp521r1";
			default -> "secp256r1";
			}));
			return generator.generateKeyPair();
		}
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		return generator.generateKeyPair();
	}
}
