package io.mosip.kernel.auth.defaultadapter.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

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
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.sun.net.httpserver.HttpServer;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.helper.ValidateTokenHelper;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
public class ValidateTokenHelperNimbusAndHmacTest {

	private static final Provider BC = new BouncyCastleProvider();

	private static final String HS384_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";
	private static final String HS512_SECRET = HS384_SECRET + "0123456789abcdef";

	@Autowired
	private ValidateTokenHelper validateTokenHelper;

	private HttpServer server;

	@Test
	public void isTokenValidWithEd25519AlgoThenPassTest() throws Exception {
		OctetKeyPair okp = newEd25519Key();

		assertThat(isTokenValidWithKeySet(signedEd25519Token(okp), new JWKSet(okp)).left, is(true));
	}

	@Test
	public void isTokenValidWithES256KAlgoThenPassTest() throws Exception {
		ECKey ecKey = newES256KKey();

		assertThat(isTokenValidWithKeySet(signedES256KToken(ecKey), new JWKSet(ecKey)).left, is(true));
	}

	@Test
	public void isTokenValidWithEd25519TokenAndWrongKeyThenUnauthorizedTest() throws Exception {
		OctetKeyPair okp = newEd25519Key();
		OctetKeyPair wrongKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID(okp.getKeyID()).generate();

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithKeySet(signedEd25519Token(okp),
				new JWKSet(wrongKey));
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValidWithES256KTokenAndWrongKeyThenUnauthorizedTest() throws Exception {
		ECKey ecKey = newES256KKey();
		ECKey wrongKey = new ECKeyGenerator(Curve.SECP256K1).provider(BC).keyID(ecKey.getKeyID()).generate();

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithKeySet(signedES256KToken(ecKey),
				new JWKSet(wrongKey));
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValidWithEd25519TokenAndUnknownKeyIdThenUnauthorizedTest() throws Exception {
		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithKeySet(signedEd25519Token(newEd25519Key()),
				new JWKSet(newEd25519Key()));
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValidWithEd25519TokenAndUnreachableCertsEndpointThenUnauthorizedTest() throws Exception {
		OctetKeyPair okp = newEd25519Key();
		String token = signedEd25519Token(okp);
		String certsUrlOfStoppedServer = startJwksServer(new JWKSet(okp));
		server.stop(0);

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithCertsUrl(token, certsUrlOfStoppedServer);
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void getPublicKeyWithEd25519TokenThenNullWithoutDownloadingKeyTest() throws Exception {
		assertNull(validateTokenHelper.getPublicKey(JWT.decode(signedEd25519Token(newEd25519Key()))));
	}

	@Test
	public void getPublicKeyWithES256KTokenThenNullWithoutDownloadingKeyTest() throws Exception {
		assertNull(validateTokenHelper.getPublicKey(JWT.decode(signedES256KToken(newES256KKey()))));
	}

	@Test
	public void isTokenValidWithHS384AndConfiguredSecretThenPassTest() {
		assertThat(isTokenValidWithHmacSecret(hmacToken("HS384", HS384_SECRET), HS384_SECRET).left, is(true));
	}

	@Test
	public void isTokenValidWithHS512AndConfiguredSecretThenPassTest() {
		assertThat(isTokenValidWithHmacSecret(hmacToken("HS512", HS512_SECRET), HS512_SECRET).left, is(true));
	}

	@Test
	public void isTokenValidWithHS512AndNoConfiguredSecretThenUnauthorizedTest() {
		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithHmacSecret(hmacToken("HS512", HS512_SECRET), "");
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValidWithHS512AndWrongSecretThenUnauthorizedTest() {
		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithHmacSecret(hmacToken("HS512", HS512_SECRET),
				HS512_SECRET.replace('0', '9'));
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValidWithHS512SignedWithPublicKeyAsSecretThenUnauthorizedTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		String forged = JWT.create().withPayload(tokenClaims())
				.sign(Algorithm.HMAC512(Base64.getEncoder().encode(kp.getPublic().getEncoded())));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithHmacSecret(forged, HS512_SECRET);
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void getPublicKeyWithHS512TokenThenNullWithoutDownloadingKeyTest() {
		assertNull(validateTokenHelper.getPublicKey(JWT.decode(hmacToken("HS512", HS512_SECRET))));
	}

	@After
	public void stopJwksServer() {
		if (server != null) {
			server.stop(0);
		}
	}

	private String hmacToken(String algorithm, String secret) {
		byte[] key = secret.getBytes(StandardCharsets.UTF_8);
		return JWT.create().withPayload(tokenClaims())
				.sign("HS384".equals(algorithm) ? Algorithm.HMAC384(key) : Algorithm.HMAC512(key));
	}

	private ImmutablePair<Boolean, AuthAdapterErrorCode> isTokenValidWithHmacSecret(String token, String secret) {
		Object originalSecret = ReflectionTestUtils.getField(validateTokenHelper, "hmacSecret");
		ReflectionTestUtils.setField(validateTokenHelper, "hmacSecret", secret);
		try {
			return validateTokenHelper.isTokenValid(JWT.decode(token), null);
		} finally {
			ReflectionTestUtils.setField(validateTokenHelper, "hmacSecret", originalSecret);
		}
	}

	private OctetKeyPair newEd25519Key() throws Exception {
		return new OctetKeyPairGenerator(Curve.Ed25519).keyID(UUID.randomUUID().toString()).generate();
	}

	private ECKey newES256KKey() throws Exception {
		return new ECKeyGenerator(Curve.SECP256K1).provider(BC).keyID(UUID.randomUUID().toString()).generate();
	}

	private ImmutablePair<Boolean, AuthAdapterErrorCode> isTokenValidWithKeySet(String token, JWKSet keySet) throws Exception {
		return isTokenValidWithCertsUrl(token, startJwksServer(keySet));
	}

	private ImmutablePair<Boolean, AuthAdapterErrorCode> isTokenValidWithCertsUrl(String token, String url) {
		Object originalCertsUrl = ReflectionTestUtils.getField(validateTokenHelper, "certsUrl");
		ReflectionTestUtils.setField(validateTokenHelper, "certsUrl", url);
		try {
			return validateTokenHelper.isTokenValid(JWT.decode(token), null);
		} finally {
			ReflectionTestUtils.setField(validateTokenHelper, "certsUrl", originalCertsUrl);
		}
	}

	private String startJwksServer(JWKSet keySet) throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/certs", exchange -> {
			byte[] bytes = keySet.toString().getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, bytes.length);
			exchange.getResponseBody().write(bytes);
			exchange.close();
		});
		server.start();
		return "http://127.0.0.1:" + server.getAddress().getPort() + "/certs";
	}

	private Map<String, Object> tokenClaims() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user");
		claims.put(AuthAdapterConstant.AZP, "account");
		claims.put(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/");
		claims.put("sub", "mock-user");
		claims.put("aud", "account");
		claims.put("iat", Instant.now().getEpochSecond());
		claims.put("exp", Instant.now().plusSeconds(345600).getEpochSecond());
		return claims;
	}

	/** Nimbus cannot sign with the Ed25519 name, so the token is built by hand. */
	private String signedEd25519Token(OctetKeyPair okp) throws Exception {
		String header = Base64URL.encode("{\"alg\":\"Ed25519\",\"kid\":\"" + okp.getKeyID() + "\"}").toString();
		String payload = new Payload(tokenClaims()).toBase64URL().toString();
		Base64URL signature = new Ed25519Signer(okp).sign(new JWSHeader(JWSAlgorithm.EdDSA),
				(header + "." + payload).getBytes(StandardCharsets.US_ASCII));
		return header + "." + payload + "." + signature;
	}

	private String signedES256KToken(ECKey ecKey) throws Exception {
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256K).keyID(ecKey.getKeyID()).build(),
				new Payload(tokenClaims()));
		ECDSASigner signer = new ECDSASigner(ecKey);
		signer.getJCAContext().setProvider(BC);
		jws.sign(signer);
		return jws.serialize();
	}
}
