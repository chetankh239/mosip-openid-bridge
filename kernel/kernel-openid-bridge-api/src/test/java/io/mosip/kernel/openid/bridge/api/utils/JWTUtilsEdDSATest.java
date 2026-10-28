package io.mosip.kernel.openid.bridge.api.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;

/**
 * Verifies EdDSA signature checking, which is done by nimbus-jose-jwt because
 * java-jwt does not support it, and the loading of OKP keys from a JWKS entry.
 */
public class JWTUtilsEdDSATest {

	private static OctetKeyPair signingKey;
	private static OctetKeyPair otherKey;
	private static KeyPair rsaKeyPair;
	private static KeyPair ecKeyPair;

	@BeforeClass
	public static void init() throws Exception {
		signingKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("signing-key").generate();
		otherKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("other-key").generate();
		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(2048);
		rsaKeyPair = rsa.generateKeyPair();
		KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
		ec.initialize(new ECGenParameterSpec("secp256r1"));
		ecKeyPair = ec.generateKeyPair();
	}

	@Test
	public void getVerificationAlgorithm_withValidSignature_thenPass() throws Exception {
		DecodedJWT token = JWT.decode(sign(signingKey, "mock-user"));

		JWTUtils.getVerificationAlgorithm("EdDSA", okpPublicKey(signingKey)).verify(token);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithm_withWrongKey_thenFail() throws Exception {
		DecodedJWT token = JWT.decode(sign(signingKey, "mock-user"));

		JWTUtils.getVerificationAlgorithm("EdDSA", okpPublicKey(otherKey)).verify(token);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithm_withTamperedPayload_thenFail() throws Exception {
		String[] original = sign(signingKey, "mock-user").split("\\.");
		String[] other = sign(signingKey, "other-user").split("\\.");
		DecodedJWT tampered = JWT.decode(original[0] + "." + other[1] + "." + original[2]);

		JWTUtils.getVerificationAlgorithm("EdDSA", okpPublicKey(signingKey)).verify(tampered);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithm_withNullKey_thenFail() throws Exception {
		DecodedJWT token = JWT.decode(sign(signingKey, "mock-user"));

		JWTUtils.getVerificationAlgorithm("EdDSA", null).verify(token);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithm_withKeyOfOtherCurve_thenFail() throws Exception {
		DecodedJWT token = JWT.decode(sign(signingKey, "mock-user"));
		OctetKeyPair ed448Key = new OctetKeyPair.Builder(Curve.Ed448, Base64URL.encode(new byte[57])).build();

		JWTUtils.getVerificationAlgorithm("EdDSA", new OctetKeyPairPublicKey(ed448Key)).verify(token);
	}

	@Test(expected = SignatureVerificationException.class)
	public void getVerificationAlgorithm_withTokenOfOtherAlgorithm_thenFail() throws Exception {
		String rs256Token = JWT.create().withSubject("mock-user").sign(
				Algorithm.RSA256((RSAPublicKey) rsaKeyPair.getPublic(), (java.security.interfaces.RSAPrivateKey) rsaKeyPair.getPrivate()));

		JWTUtils.getVerificationAlgorithm("EdDSA", okpPublicKey(signingKey)).verify(JWT.decode(rs256Token));
	}

	@Test(expected = AlgorithmMismatchException.class)
	public void getVerificationAlgorithm_withRSAKeyForEdDSAToken_thenFail() {
		JWTUtils.getVerificationAlgorithm("EdDSA", rsaKeyPair.getPublic());
	}

	@Test(expected = AlgorithmMismatchException.class)
	public void getVerificationAlgorithm_withOKPKeyForRS256Token_thenFail() throws Exception {
		JWTUtils.getVerificationAlgorithm("RS256", okpPublicKey(signingKey));
	}

	@Test(expected = SignatureGenerationException.class)
	public void sign_thenNotSupported() throws Exception {
		JWTUtils.getVerificationAlgorithm("EdDSA", okpPublicKey(signingKey)).sign(new byte[0]);
	}

	@Test
	public void toPublicKey_withOKPKey_thenReturnKeyThatVerifiesTokens() throws Exception {
		PublicKey publicKey = JWTUtils.toPublicKey(Jwk.fromValues(signingKey.toPublicJWK().toJSONObject()));

		assertEquals("EdDSA", publicKey.getAlgorithm());
		assertNull(publicKey.getFormat());
		assertNull(publicKey.getEncoded());
		JWTUtils.getVerificationAlgorithm("EdDSA", publicKey).verify(JWT.decode(sign(signingKey, "mock-user")));
	}

	@Test
	public void toPublicKey_withOKPKeyWithoutKeyId_thenReturnKey() throws Exception {
		Map<String, Object> values = new HashMap<>(signingKey.toPublicJWK().toJSONObject());
		values.remove("kid");

		PublicKey publicKey = JWTUtils.toPublicKey(Jwk.fromValues(values));

		JWTUtils.getVerificationAlgorithm("EdDSA", publicKey).verify(JWT.decode(sign(signingKey, "mock-user")));
	}

	@Test
	public void toPublicKey_withOKPKeyContainingPrivatePart_thenKeepOnlyPublicPart() throws Exception {
		PublicKey publicKey = JWTUtils.toPublicKey(Jwk.fromValues(signingKey.toJSONObject()));

		assertFalse(((OctetKeyPairPublicKey) publicKey).getOctetKeyPair().isPrivate());
	}

	@Test(expected = InvalidPublicKeyException.class)
	public void toPublicKey_withInvalidOKPKey_thenFail() throws Exception {
		Map<String, Object> values = new HashMap<>(signingKey.toPublicJWK().toJSONObject());
		values.remove("x");

		JWTUtils.toPublicKey(Jwk.fromValues(values));
	}

	@Test
	public void toPublicKey_withRSAKey_thenReturnRSAPublicKey() throws Exception {
		RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) rsaKeyPair.getPublic()).keyID("rsa-key").build();

		PublicKey publicKey = JWTUtils.toPublicKey(Jwk.fromValues(rsaKey.toJSONObject()));

		assertTrue(publicKey instanceof RSAPublicKey);
		assertEquals(rsaKeyPair.getPublic(), publicKey);
	}

	@Test
	public void toPublicKey_withECKey_thenReturnECPublicKey() throws Exception {
		ECKey ecKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) ecKeyPair.getPublic()).keyID("ec-key").build();

		PublicKey publicKey = JWTUtils.toPublicKey(Jwk.fromValues(ecKey.toJSONObject()));

		assertTrue(publicKey instanceof ECPublicKey);
		assertEquals(ecKeyPair.getPublic(), publicKey);
	}

	private PublicKey okpPublicKey(OctetKeyPair key) {
		return new OctetKeyPairPublicKey(key);
	}

	private String sign(OctetKeyPair key, String subject) throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put("sub", subject);
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(key.getKeyID()).build(),
				new Payload(claims));
		jws.sign(new Ed25519Signer(key));
		return jws.serialize();
	}
}
