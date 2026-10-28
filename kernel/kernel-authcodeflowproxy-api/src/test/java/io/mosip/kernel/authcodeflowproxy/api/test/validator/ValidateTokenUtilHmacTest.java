package io.mosip.kernel.authcodeflowproxy.api.test.validator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import io.mosip.kernel.authcodeflowproxy.api.validator.ValidateTokenUtil;
import io.mosip.kernel.openid.bridge.api.constants.AuthErrorCode;

/**
 * Verifies that HS384 and HS512 signed tokens are checked only against the
 * configured shared secret.
 */
public class ValidateTokenUtilHmacTest {

	private static final String HS384_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";
	private static final String HS512_SECRET = HS384_SECRET + "0123456789abcdef";

	private ValidateTokenUtil validateTokenUtil;

	@Before
	public void setUp() {
		validateTokenUtil = new ValidateTokenUtil();
	}

	@Test
	public void verifyJWTSignagure_withHS384AndConfiguredSecret_thenPass() {
		ReflectionTestUtils.setField(validateTokenUtil, "hmacSecret", HS384_SECRET);

		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil.verifyJWTSignagure(JWT.decode(
				JWT.create().withSubject("mock-user").sign(Algorithm.HMAC384(HS384_SECRET.getBytes(StandardCharsets.UTF_8)))));

		assertTrue(res.getLeft());
		assertNull(res.getRight());
	}

	@Test
	public void verifyJWTSignagure_withHS512AndConfiguredSecret_thenPass() {
		ReflectionTestUtils.setField(validateTokenUtil, "hmacSecret", HS512_SECRET);

		assertTrue(validateTokenUtil.verifyJWTSignagure(JWT.decode(hs512(HS512_SECRET))).getLeft());
	}

	@Test
	public void verifyJWTSignagure_withHS512AndNoConfiguredSecret_thenUnauthorized() {
		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil.verifyJWTSignagure(JWT.decode(hs512(HS512_SECRET)));

		assertFalse(res.getLeft());
		assertEquals(AuthErrorCode.UNAUTHORIZED, res.getRight());
	}

	@Test
	public void verifyJWTSignagure_withHS512AndWrongSecret_thenUnauthorized() {
		ReflectionTestUtils.setField(validateTokenUtil, "hmacSecret", HS512_SECRET.replace('0', '9'));

		ImmutablePair<Boolean, AuthErrorCode> res = validateTokenUtil.verifyJWTSignagure(JWT.decode(hs512(HS512_SECRET)));

		assertFalse(res.getLeft());
		assertEquals(AuthErrorCode.UNAUTHORIZED, res.getRight());
	}

	@Test
	public void getPublicKey_withHS512Token_thenNullWithoutDownloadingKey() {
		assertNull(validateTokenUtil.getPublicKey(JWT.decode(hs512(HS512_SECRET))));
	}

	private String hs512(String secret) {
		return JWT.create().withSubject("mock-user").sign(Algorithm.HMAC512(secret.getBytes(StandardCharsets.UTF_8)));
	}
}
