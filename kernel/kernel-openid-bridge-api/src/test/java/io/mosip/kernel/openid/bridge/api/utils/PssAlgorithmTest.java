package io.mosip.kernel.openid.bridge.api.utils;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import org.junit.Before;
import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class PssAlgorithmTest {

	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

	private KeyPair keyPair;

	@Before
	public void setUp() throws Exception {
		keyPair = newKeyPair();
	}

	@Test
	public void validPs256TokenVerifies() throws Exception {
		PssAlgorithm.PS256(keyPair.getPublic()).verify(JWT.decode(token("PS256", keyPair, "{\"sub\":\"user\"}")));
	}

	@Test
	public void validPs384AndPs512TokensVerify() throws Exception {
		PssAlgorithm.PS384(keyPair.getPublic()).verify(JWT.decode(token("PS384", keyPair, "{\"sub\":\"user\"}")));
		PssAlgorithm.PS512(keyPair.getPublic()).verify(JWT.decode(token("PS512", keyPair, "{\"sub\":\"user\"}")));
	}

	@Test(expected = SignatureVerificationException.class)
	public void tokenSignedWithAnotherKeyIsRejected() throws Exception {
		PssAlgorithm.PS256(keyPair.getPublic()).verify(JWT.decode(token("PS256", newKeyPair(), "{\"sub\":\"user\"}")));
	}

	@Test(expected = SignatureVerificationException.class)
	public void tamperedPayloadIsRejected() throws Exception {
		String[] parts = token("PS256", keyPair, "{\"sub\":\"user\"}").split("\\.");
		DecodedJWT tampered = JWT
				.decode(parts[0] + "." + ENCODER.encodeToString("{\"sub\":\"admin\"}".getBytes(UTF_8)) + "." + parts[2]);
		PssAlgorithm.PS256(keyPair.getPublic()).verify(tampered);
	}

	@Test(expected = SignatureVerificationException.class)
	public void differentHashAlgorithmIsRejected() throws Exception {
		PssAlgorithm.PS384(keyPair.getPublic()).verify(JWT.decode(token("PS256", keyPair, "{\"sub\":\"user\"}")));
	}

	@Test(expected = SignatureVerificationException.class)
	public void missingPublicKeyIsRejected() throws Exception {
		PssAlgorithm.PS256(null).verify(JWT.decode(token("PS256", keyPair, "{\"sub\":\"user\"}")));
	}

	@Test(expected = SignatureGenerationException.class)
	public void signingIsNotSupported() {
		PssAlgorithm.PS256(keyPair.getPublic()).sign(new byte[0]);
	}

	private KeyPair newKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	private String token(String algorithm, KeyPair signingKeys, String payload) throws Exception {
		String signingInput = ENCODER.encodeToString(("{\"alg\":\"" + algorithm + "\",\"kid\":\"k\"}").getBytes(UTF_8))
				+ "." + ENCODER.encodeToString(payload.getBytes(UTF_8));
		PSSParameterSpec spec;
		switch (algorithm) {
		case "PS384":
			spec = new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
			break;
		case "PS512":
			spec = new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
			break;
		default:
			spec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
		}
		Signature signature = Signature.getInstance("RSASSA-PSS");
		signature.setParameter(spec);
		signature.initSign(signingKeys.getPrivate());
		signature.update(signingInput.getBytes(UTF_8));
		return signingInput + "." + ENCODER.encodeToString(signature.sign());
	}
}
