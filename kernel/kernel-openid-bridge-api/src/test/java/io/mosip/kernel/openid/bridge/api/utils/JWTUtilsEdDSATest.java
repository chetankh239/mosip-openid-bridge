package io.mosip.kernel.openid.bridge.api.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.sun.net.httpserver.HttpServer;

/**
 * Verifies EdDSA signature checking and loading of OKP keys, which are done with
 * nimbus-jose-jwt because java-jwt and the JWKS library do not support them.
 */
public class JWTUtilsEdDSATest {

	private static KeyPair rsaKeyPair;

	private HttpServer server;
	private final AtomicInteger requests = new AtomicInteger();

	@BeforeClass
	public static void init() throws Exception {
		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(2048);
		rsaKeyPair = rsa.generateKeyPair();
	}

	@After
	public void stopServer() {
		if (server != null) {
			server.stop(0);
		}
	}

	@Test
	public void isEdDSAToken_withEdDSAToken_thenTrue() throws Exception {
		assertTrue(JWTUtils.isEdDSAToken(JWT.decode(sign(newKey("k1"), "mock-user"))));
	}

	@Test
	public void isEdDSAToken_withRS256Token_thenFalse() {
		String token = JWT.create().withSubject("mock-user").sign(Algorithm.RSA256((RSAPublicKey) rsaKeyPair.getPublic(),
				(RSAPrivateKey) rsaKeyPair.getPrivate()));

		assertFalse(JWTUtils.isEdDSAToken(JWT.decode(token)));
	}

	@Test
	public void isEdDSASignatureValid_withValidSignature_thenTrue() throws Exception {
		OctetKeyPair key = newKey("k1");

		assertTrue(JWTUtils.isEdDSASignatureValid(JWT.decode(sign(key, "mock-user")), key.toPublicJWK()));
	}

	@Test
	public void isEdDSASignatureValid_withWrongKey_thenFalse() throws Exception {
		assertFalse(JWTUtils.isEdDSASignatureValid(JWT.decode(sign(newKey("k1"), "mock-user")),
				newKey("k2").toPublicJWK()));
	}

	@Test
	public void isEdDSASignatureValid_withTamperedPayload_thenFalse() throws Exception {
		OctetKeyPair key = newKey("k1");
		String[] original = sign(key, "mock-user").split("\\.");
		String[] other = sign(key, "other-user").split("\\.");

		assertFalse(JWTUtils.isEdDSASignatureValid(JWT.decode(original[0] + "." + other[1] + "." + original[2]),
				key.toPublicJWK()));
	}

	@Test
	public void isEdDSASignatureValid_withNullKey_thenFalse() throws Exception {
		assertFalse(JWTUtils.isEdDSASignatureValid(JWT.decode(sign(newKey("k1"), "mock-user")), null));
	}

	@Test
	public void isEdDSASignatureValid_withKeyOfOtherCurve_thenFalse() throws Exception {
		OctetKeyPair ed448Key = new OctetKeyPair.Builder(Curve.Ed448, Base64URL.encode(new byte[57])).build();

		assertFalse(JWTUtils.isEdDSASignatureValid(JWT.decode(sign(newKey("k1"), "mock-user")), ed448Key));
	}

	@Test
	public void isEdDSASignatureValid_withTokenOfOtherAlgorithm_thenFalse() throws Exception {
		String rs256Token = JWT.create().withSubject("mock-user").sign(Algorithm
				.RSA256((RSAPublicKey) rsaKeyPair.getPublic(), (RSAPrivateKey) rsaKeyPair.getPrivate()));

		assertFalse(JWTUtils.isEdDSASignatureValid(JWT.decode(rs256Token), newKey("k1").toPublicJWK()));
	}

	@Test
	public void getOctetKeyPair_withKnownKeyId_thenReturnPublicKeyOnly() throws Exception {
		OctetKeyPair key = newKey(UUID.randomUUID().toString());
		String url = serveJwks(new JWKSet(key));

		OctetKeyPair publicKey = JWTUtils.getOctetKeyPair(url, key.getKeyID());

		assertNotNull(publicKey);
		assertFalse(publicKey.isPrivate());
		assertEquals(key.getX(), publicKey.getX());
	}

	@Test
	public void getOctetKeyPair_calledTwice_thenDownloadsOnce() throws Exception {
		OctetKeyPair key = newKey(UUID.randomUUID().toString());
		String url = serveJwks(new JWKSet(key));

		JWTUtils.getOctetKeyPair(url, key.getKeyID());
		JWTUtils.getOctetKeyPair(url, key.getKeyID());

		assertEquals(1, requests.get());
	}

	@Test
	public void getOctetKeyPair_withUnknownKeyId_thenNull() throws Exception {
		String url = serveJwks(new JWKSet(newKey(UUID.randomUUID().toString())));

		assertNull(JWTUtils.getOctetKeyPair(url, "unknown"));
	}

	@Test
	public void getOctetKeyPair_withNonOKPKey_thenNull() throws Exception {
		String kid = UUID.randomUUID().toString();
		String url = serveJwks(new JWKSet(new RSAKey.Builder((RSAPublicKey) rsaKeyPair.getPublic()).keyID(kid).build()));

		assertNull(JWTUtils.getOctetKeyPair(url, kid));
	}

	@Test(expected = IOException.class)
	public void getOctetKeyPair_withUnreachableEndpoint_thenFail() throws Exception {
		String url = serveJwks(new JWKSet());
		server.stop(0);

		JWTUtils.getOctetKeyPair(url, UUID.randomUUID().toString());
	}

	@Test(expected = ParseException.class)
	public void getOctetKeyPair_withInvalidKeySet_thenFail() throws Exception {
		JWTUtils.getOctetKeyPair(serve("not a key set"), UUID.randomUUID().toString());
	}

	@Test(expected = URISyntaxException.class)
	public void getOctetKeyPair_withInvalidUrl_thenFail() throws Exception {
		JWTUtils.getOctetKeyPair("http://invalid host/certs", UUID.randomUUID().toString());
	}

	private OctetKeyPair newKey(String keyId) throws Exception {
		return new OctetKeyPairGenerator(Curve.Ed25519).keyID(keyId).generate();
	}

	private String sign(OctetKeyPair key, String subject) throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put("sub", subject);
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(key.getKeyID()).build(),
				new Payload(claims));
		jws.sign(new Ed25519Signer(key));
		return jws.serialize();
	}

	private String serveJwks(JWKSet keySet) throws IOException {
		return serve(keySet.toString());
	}

	private String serve(String body) throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/certs", exchange -> {
			requests.incrementAndGet();
			byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, bytes.length);
			exchange.getResponseBody().write(bytes);
			exchange.close();
		});
		server.start();
		return "http://127.0.0.1:" + server.getAddress().getPort() + "/certs";
	}
}
