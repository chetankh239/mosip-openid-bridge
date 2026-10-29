package io.mosip.kernel.authcodeflowproxy.api.test.validator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.UUID;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

import com.auth0.jwt.JWT;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.sun.net.httpserver.HttpServer;

import io.mosip.kernel.authcodeflowproxy.api.validator.ValidateTokenUtil;
import io.mosip.kernel.openid.bridge.api.constants.AuthErrorCode;

public class ValidateTokenUtilNimbusTest {

	private static final Provider BC = new BouncyCastleProvider();

	private ValidateTokenUtil validateTokenUtil;
	private HttpServer server;

	@Before
	public void setUp() {
		validateTokenUtil = new ValidateTokenUtil();
	}

	@After
	public void stopServer() {
		if (server != null) {
			server.stop(0);
		}
	}

	@Test
	public void verifyJWTSignagureWithEd25519TokenThenPassTest() throws Exception {
		OctetKeyPair key = ed25519Key();
		serve(new JWKSet(key));

		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil
				.verifyJWTSignagure(JWT.decode(signEd25519(key)));

		assertTrue(res.getLeft());
		assertNull(res.getRight());
	}

	@Test
	public void verifyJWTSignagureWithES256KTokenThenPassTest() throws Exception {
		ECKey key = es256kKey();
		serve(new JWKSet(key));

		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil
				.verifyJWTSignagure(JWT.decode(signES256K(key)));

		assertTrue(res.getLeft());
		assertNull(res.getRight());
	}

	@Test
	public void verifyJWTSignagureWithEd25519TokenAndWrongKeyThenUnauthorizedTest() throws Exception {
		OctetKeyPair key = ed25519Key();
		serve(new JWKSet(new OctetKeyPairGenerator(Curve.Ed25519).keyID(key.getKeyID()).generate()));

		assertUnauthorized(validateTokenUtil.verifyJWTSignagure(JWT.decode(signEd25519(key))));
	}

	@Test
	public void verifyJWTSignagureWithES256KTokenAndWrongKeyThenUnauthorizedTest() throws Exception {
		ECKey key = es256kKey();
		serve(new JWKSet(new ECKeyGenerator(Curve.SECP256K1).provider(BC).keyID(key.getKeyID()).generate()));

		assertUnauthorized(validateTokenUtil.verifyJWTSignagure(JWT.decode(signES256K(key))));
	}

	@Test
	public void verifyJWTSignagureWithEd25519TokenAndUnknownKeyIdThenUnauthorizedTest() throws Exception {
		OctetKeyPair key = ed25519Key();
		serve(new JWKSet(ed25519Key()));

		assertUnauthorized(validateTokenUtil.verifyJWTSignagure(JWT.decode(signEd25519(key))));
	}

	@Test
	public void verifyJWTSignagureWithEd25519TokenAndUnreachableEndpointThenUnauthorizedTest() throws Exception {
		OctetKeyPair key = ed25519Key();
		serve(new JWKSet(key));
		server.stop(0);

		assertUnauthorized(validateTokenUtil.verifyJWTSignagure(JWT.decode(signEd25519(key))));
	}

	@Test
	public void getPublicKeyWithEd25519AndES256KTokensThenNullWithoutDownloadingKeyTest() throws Exception {
		assertNull(validateTokenUtil.getPublicKey(JWT.decode(signEd25519(ed25519Key()))));
		assertNull(validateTokenUtil.getPublicKey(JWT.decode(signES256K(es256kKey()))));
	}

	private void assertUnauthorized(ImmutablePair<Boolean, AuthErrorCode> res) {
		assertFalse(res.getLeft());
		assertEquals(AuthErrorCode.UNAUTHORIZED, res.getRight());
	}

	private OctetKeyPair ed25519Key() throws Exception {
		return new OctetKeyPairGenerator(Curve.Ed25519).keyID(UUID.randomUUID().toString()).generate();
	}

	private ECKey es256kKey() throws Exception {
		return new ECKeyGenerator(Curve.SECP256K1).provider(BC).keyID(UUID.randomUUID().toString()).generate();
	}

	/** Nimbus cannot sign with the Ed25519 name, so the token is built by hand. */
	private String signEd25519(OctetKeyPair key) throws Exception {
		String header = Base64URL.encode("{\"alg\":\"Ed25519\",\"kid\":\"" + key.getKeyID() + "\"}").toString();
		String payload = Base64URL.encode("{\"sub\":\"mock-user\"}").toString();
		Base64URL signature = new Ed25519Signer(key).sign(new JWSHeader(JWSAlgorithm.EdDSA),
				(header + "." + payload).getBytes(StandardCharsets.US_ASCII));
		return header + "." + payload + "." + signature;
	}

	private String signES256K(ECKey key) throws Exception {
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256K).keyID(key.getKeyID()).build(),
				new Payload(java.util.Map.of("sub", "mock-user")));
		ECDSASigner signer = new ECDSASigner(key);
		signer.getJCAContext().setProvider(BC);
		jws.sign(signer);
		return jws.serialize();
	}

	private void serve(JWKSet keySet) throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/certs", exchange -> {
			byte[] bytes = keySet.toString().getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, bytes.length);
			exchange.getResponseBody().write(bytes);
			exchange.close();
		});
		server.start();
		ReflectionTestUtils.setField(validateTokenUtil, "certsPathUrl",
				"http://127.0.0.1:" + server.getAddress().getPort() + "/certs");
	}
}
