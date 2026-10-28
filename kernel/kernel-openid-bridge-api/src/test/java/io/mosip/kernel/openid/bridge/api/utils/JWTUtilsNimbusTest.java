package io.mosip.kernel.openid.bridge.api.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.sun.net.httpserver.HttpServer;

/**
 * Verifies Ed25519 and ES256K signature checking and loading of their keys, which
 * are done with nimbus-jose-jwt because java-jwt and the JWKS library do not
 * support them.
 */
public class JWTUtilsNimbusTest {

	private static final Provider BC = new BouncyCastleProvider();

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
	public void isNimbusToken_withEd25519AndES256KTokens_thenTrue() throws Exception {
		assertTrue(JWTUtils.isNimbusToken(JWT.decode(signEd25519(ed25519Key(), "mock-user"))));
		assertTrue(JWTUtils.isNimbusToken(JWT.decode(signES256K(es256kKey(), "mock-user"))));
	}

	@Test
	public void isNimbusToken_withOtherAlgorithms_thenFalse() throws Exception {
		String rs256Token = JWT.create().withSubject("mock-user").sign(Algorithm
				.RSA256((RSAPublicKey) rsaKeyPair.getPublic(), (RSAPrivateKey) rsaKeyPair.getPrivate()));
		assertFalse(JWTUtils.isNimbusToken(JWT.decode(rs256Token)));
		assertFalse(JWTUtils.isNimbusToken(JWT.decode(signEdDSA(ed25519Key()))));
	}

	@Test
	public void isNimbusSignatureValid_withEd25519_thenTrue() throws Exception {
		OctetKeyPair key = ed25519Key();

		assertTrue(JWTUtils.isNimbusSignatureValid(JWT.decode(signEd25519(key, "mock-user")), key.toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withEd25519AndWrongKey_thenFalse() throws Exception {
		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signEd25519(ed25519Key(), "mock-user")),
				ed25519Key().toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withEd25519AndTamperedPayload_thenFalse() throws Exception {
		OctetKeyPair key = ed25519Key();
		String[] original = signEd25519(key, "mock-user").split("\\.");
		String[] other = signEd25519(key, "other-user").split("\\.");

		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(original[0] + "." + other[1] + "." + original[2]),
				key.toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withEd25519AndKeyOfOtherCurve_thenFalse() throws Exception {
		OctetKeyPair ed448Key = new OctetKeyPair.Builder(Curve.Ed448, Base64URL.encode(new byte[57])).build();

		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signEd25519(ed25519Key(), "mock-user")), ed448Key));
	}

	@Test
	public void isNimbusSignatureValid_withEd25519AndKeyOfOtherType_thenFalse() throws Exception {
		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signEd25519(ed25519Key(), "mock-user")),
				es256kKey().toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withEdDSAToken_thenFalse() throws Exception {
		OctetKeyPair key = ed25519Key();

		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signEdDSA(key)), key.toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withES256K_thenTrue() throws Exception {
		ECKey key = es256kKey();

		assertTrue(JWTUtils.isNimbusSignatureValid(JWT.decode(signES256K(key, "mock-user")), key.toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withES256KAndWrongKey_thenFalse() throws Exception {
		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signES256K(es256kKey(), "mock-user")),
				es256kKey().toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withES256KAndTamperedPayload_thenFalse() throws Exception {
		ECKey key = es256kKey();
		String[] original = signES256K(key, "mock-user").split("\\.");
		String[] other = signES256K(key, "other-user").split("\\.");

		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(original[0] + "." + other[1] + "." + original[2]),
				key.toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withES256KAndKeyOfOtherCurve_thenFalse() throws Exception {
		ECKey p256Key = new ECKeyGenerator(Curve.P_256).keyID("p256").generate();

		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signES256K(es256kKey(), "mock-user")),
				p256Key.toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withES256KAndKeyOfOtherType_thenFalse() throws Exception {
		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signES256K(es256kKey(), "mock-user")),
				ed25519Key().toPublicJWK()));
	}

	@Test
	public void isNimbusSignatureValid_withNullKey_thenFalse() throws Exception {
		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signEd25519(ed25519Key(), "mock-user")), null));
		assertFalse(JWTUtils.isNimbusSignatureValid(JWT.decode(signES256K(es256kKey(), "mock-user")), null));
	}

	@Test
	public void getPublicJWK_withEd25519Key_thenReturnPublicKeyOnly() throws Exception {
		OctetKeyPair key = new OctetKeyPairGenerator(Curve.Ed25519).keyID(UUID.randomUUID().toString()).generate();
		String url = serve(new JWKSet(key).toString());

		JWK publicKey = JWTUtils.getPublicJWK(url, key.getKeyID());

		assertTrue(publicKey instanceof OctetKeyPair);
		assertFalse(publicKey.isPrivate());
		assertEquals(key.getX(), ((OctetKeyPair) publicKey).getX());
	}

	@Test
	public void getPublicJWK_withES256KKey_thenReturnPublicKeyOnly() throws Exception {
		ECKey key = new ECKeyGenerator(Curve.SECP256K1).provider(BC).keyID(UUID.randomUUID().toString()).generate();
		String url = serve(new JWKSet(key).toString());

		JWK publicKey = JWTUtils.getPublicJWK(url, key.getKeyID());

		assertTrue(publicKey instanceof ECKey);
		assertFalse(publicKey.isPrivate());
		assertEquals(Curve.SECP256K1, ((ECKey) publicKey).getCurve());
	}

	@Test
	public void getPublicJWK_calledTwice_thenDownloadsOnce() throws Exception {
		OctetKeyPair key = new OctetKeyPairGenerator(Curve.Ed25519).keyID(UUID.randomUUID().toString()).generate();
		String url = serve(new JWKSet(key).toString());

		JWTUtils.getPublicJWK(url, key.getKeyID());
		JWTUtils.getPublicJWK(url, key.getKeyID());

		assertEquals(1, requests.get());
	}

	@Test
	public void getPublicJWK_withUnknownKeyId_thenNull() throws Exception {
		String url = serve(new JWKSet(ed25519Key()).toString());

		assertNull(JWTUtils.getPublicJWK(url, "unknown"));
	}

	@Test(expected = IOException.class)
	public void getPublicJWK_withUnreachableEndpoint_thenFail() throws Exception {
		String url = serve(new JWKSet().toString());
		server.stop(0);

		JWTUtils.getPublicJWK(url, UUID.randomUUID().toString());
	}

	@Test(expected = ParseException.class)
	public void getPublicJWK_withInvalidKeySet_thenFail() throws Exception {
		JWTUtils.getPublicJWK(serve("not a key set"), UUID.randomUUID().toString());
	}

	@Test(expected = URISyntaxException.class)
	public void getPublicJWK_withInvalidUrl_thenFail() throws Exception {
		JWTUtils.getPublicJWK("http://invalid host/certs", UUID.randomUUID().toString());
	}

	private OctetKeyPair ed25519Key() throws Exception {
		return new OctetKeyPairGenerator(Curve.Ed25519).keyID(UUID.randomUUID().toString()).generate();
	}

	private ECKey es256kKey() throws Exception {
		return new ECKeyGenerator(Curve.SECP256K1).provider(BC).keyID(UUID.randomUUID().toString()).generate();
	}

	/** Nimbus cannot sign with the Ed25519 name, so the token is built by hand. */
	private String signEd25519(OctetKeyPair key, String subject) throws Exception {
		String header = Base64URL.encode("{\"alg\":\"Ed25519\",\"kid\":\"" + key.getKeyID() + "\"}").toString();
		String payload = Base64URL.encode("{\"sub\":\"" + subject + "\"}").toString();
		Base64URL signature = new Ed25519Signer(key).sign(new JWSHeader(JWSAlgorithm.EdDSA),
				(header + "." + payload).getBytes(StandardCharsets.US_ASCII));
		return header + "." + payload + "." + signature;
	}

	private String signEdDSA(OctetKeyPair key) throws Exception {
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(key.getKeyID()).build(),
				new Payload(Map.of("sub", "mock-user")));
		jws.sign(new Ed25519Signer(key));
		return jws.serialize();
	}

	private String signES256K(ECKey key, String subject) throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put("sub", subject);
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256K).keyID(key.getKeyID()).build(),
				new Payload(claims));
		ECDSASigner signer = new ECDSASigner(key);
		signer.getJCAContext().setProvider(BC);
		jws.sign(signer);
		return jws.serialize();
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
