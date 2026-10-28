package io.mosip.kernel.authcodeflowproxy.api.test.validator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

import com.auth0.jwt.JWT;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.sun.net.httpserver.HttpServer;

import io.mosip.kernel.authcodeflowproxy.api.validator.ValidateTokenUtil;
import io.mosip.kernel.openid.bridge.api.constants.AuthErrorCode;

/**
 * Verifies that EdDSA signed tokens are checked against the keys of the JWKS
 * endpoint.
 */
public class ValidateTokenUtilEdDSATest {

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
	public void verifyJWTSignagure_withEdDSAToken_thenPass() throws Exception {
		OctetKeyPair key = newKey();
		serve(new JWKSet(key));

		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil.verifyJWTSignagure(JWT.decode(sign(key)));

		assertTrue(res.getLeft());
		assertNull(res.getRight());
	}

	@Test
	public void verifyJWTSignagure_withEdDSATokenAndWrongKey_thenUnauthorized() throws Exception {
		OctetKeyPair key = newKey();
		serve(new JWKSet(new OctetKeyPairGenerator(Curve.Ed25519).keyID(key.getKeyID()).generate()));

		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil.verifyJWTSignagure(JWT.decode(sign(key)));

		assertFalse(res.getLeft());
		assertEquals(AuthErrorCode.UNAUTHORIZED, res.getRight());
	}

	@Test
	public void verifyJWTSignagure_withEdDSATokenAndUnknownKeyId_thenUnauthorized() throws Exception {
		OctetKeyPair key = newKey();
		serve(new JWKSet(newKey()));

		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil.verifyJWTSignagure(JWT.decode(sign(key)));

		assertFalse(res.getLeft());
		assertEquals(AuthErrorCode.UNAUTHORIZED, res.getRight());
	}

	@Test
	public void verifyJWTSignagure_withEdDSATokenAndUnreachableEndpoint_thenUnauthorized() throws Exception {
		OctetKeyPair key = newKey();
		serve(new JWKSet(key));
		server.stop(0);

		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil.verifyJWTSignagure(JWT.decode(sign(key)));

		assertFalse(res.getLeft());
		assertEquals(AuthErrorCode.UNAUTHORIZED, res.getRight());
	}

	@Test
	public void getPublicKey_withEdDSAToken_thenNullWithoutDownloadingKey() throws Exception {
		assertNull(validateTokenUtil.getPublicKey(JWT.decode(sign(newKey()))));
	}

	private OctetKeyPair newKey() throws Exception {
		return new OctetKeyPairGenerator(Curve.Ed25519).keyID(UUID.randomUUID().toString()).generate();
	}

	private String sign(OctetKeyPair key) throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put("sub", "mock-user");
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(key.getKeyID()).build(),
				new Payload(claims));
		jws.sign(new Ed25519Signer(key));
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
