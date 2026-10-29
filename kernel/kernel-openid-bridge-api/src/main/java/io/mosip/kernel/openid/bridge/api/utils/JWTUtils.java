package io.mosip.kernel.openid.bridge.api.utils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JWTUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(JWTUtils.class);
	
	private JWTUtils() {
		
	}

	private static final String ED25519_ALGORITHM = "Ed25519";
	private static final String ES256K_ALGORITHM = "ES256K";
	private static final String HS384_ALGORITHM = "HS384";
	private static final String HS512_ALGORITHM = "HS512";
	private static final int HS384_MIN_SECRET_LENGTH = 48;
	private static final int HS512_MIN_SECRET_LENGTH = 64;
	private static final int JWKS_TIMEOUT_MS = 5000;
	private static final int JWKS_SIZE_LIMIT = 51200;

	private static final Map<String, JWK> publicJWKCache = new ConcurrentHashMap<>();

	static Map<String,DecodedJWT> decodedJWTCache = new HashMap<>();
	
	public static String getissuer(String token) {
		DecodedJWT decodedJWT  = null;
		if(decodedJWTCache.get(token)!=null)
			decodedJWT = decodedJWTCache.get(token);
		else{
			decodedJWT = JWT.decode(token);
			decodedJWTCache.put(token, decodedJWT);
		}	
		return decodedJWT.getClaim("iss").asString();
	}

	public static String getSubClaimValueFromToken(String token, String propertyName) {
		return JWT.decode(token).getClaim(propertyName).asString();
	}

	/**
	 * Returns the java-jwt algorithm that verifies the token signature, chosen by the
	 * {@code alg} header: RS, PS and ES with 256, 384 and 512. Any other or missing
	 * algorithm falls back to RS256.
	 *
	 * @throws AlgorithmMismatchException if the key type does not fit the algorithm
	 */
	public static Algorithm getVerificationAlgorithm(String tokenAlgo, PublicKey publicKey) {
		String algo = tokenAlgo == null ? "" : tokenAlgo;
		return switch (algo) {
		case "RS384" -> Algorithm.RSA384(keyOfType(publicKey, RSAPublicKey.class, algo), null);
		case "RS512" -> Algorithm.RSA512(keyOfType(publicKey, RSAPublicKey.class, algo), null);
		case "PS256" -> Algorithm.RSA256PSS(keyOfType(publicKey, RSAPublicKey.class, algo), null);
		case "PS384" -> Algorithm.RSA384PSS(keyOfType(publicKey, RSAPublicKey.class, algo), null);
		case "PS512" -> Algorithm.RSA512PSS(keyOfType(publicKey, RSAPublicKey.class, algo), null);
		case "ES256" -> Algorithm.ECDSA256(keyOfType(publicKey, ECPublicKey.class, algo), null);
		case "ES384" -> Algorithm.ECDSA384(keyOfType(publicKey, ECPublicKey.class, algo), null);
		case "ES512" -> Algorithm.ECDSA512(keyOfType(publicKey, ECPublicKey.class, algo), null);
		default -> Algorithm.RSA256(keyOfType(publicKey, RSAPublicKey.class, algo), null);
		};
	}

	/** Tells whether the token is signed with Ed25519 or ES256K, which java-jwt does not support. */
	public static boolean isNimbusToken(DecodedJWT decodedJWT) {
		String algorithm = decodedJWT.getAlgorithm();
		return ED25519_ALGORITHM.equals(algorithm) || ES256K_ALGORITHM.equals(algorithm);
	}

	/**
	 * Reads the public key of a JWKS entry with nimbus, because the JWKS library used
	 * for RSA and EC keys cannot build Ed25519 or secp256k1 keys. Found keys are cached.
	 *
	 * @return the public key, or null if the endpoint has no key with this id
	 */
	public static JWK getPublicJWK(String certsUrl, String keyId)
			throws IOException, ParseException, URISyntaxException {
		String cacheKey = certsUrl + "#" + keyId;
		JWK publicKey = publicJWKCache.get(cacheKey);
		if (publicKey == null) {
			JWK jwk = JWKSet.load(new URI(certsUrl).normalize().toURL(), JWKS_TIMEOUT_MS, JWKS_TIMEOUT_MS,
					JWKS_SIZE_LIMIT).getKeyByKeyId(keyId);
			if (jwk != null) {
				publicKey = jwk.toPublicJWK();
				publicJWKCache.put(cacheKey, publicKey);
			}
		}
		return publicKey;
	}

	/**
	 * Verifies an Ed25519 or ES256K token with nimbus.
	 *
	 * @return true only if the signature is valid, false for a missing key or a key
	 *         of the wrong type or curve
	 */
	public static boolean isNimbusSignatureValid(DecodedJWT decodedJWT, JWK publicKey) {
		String tokenAlgo = decodedJWT.getAlgorithm();
		try {
			JWSVerifier verifier;
			JWSAlgorithm algorithm;
			if (ED25519_ALGORITHM.equals(tokenAlgo) && publicKey instanceof OctetKeyPair octetKeyPair) {
				verifier = new Ed25519Verifier(octetKeyPair);
				algorithm = JWSAlgorithm.EdDSA; // the name nimbus knows its Ed25519 verifier by
			} else if (ES256K_ALGORITHM.equals(tokenAlgo) && publicKey instanceof ECKey ecKey) {
				ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(ecKey);
				ecdsaVerifier.getJCAContext().setProvider(BouncyCastleHolder.PROVIDER); // the JDK has no secp256k1 curve
				verifier = ecdsaVerifier;
				algorithm = JWSAlgorithm.ES256K;
			} else {
				return false;
			}
			byte[] signingInput = (decodedJWT.getHeader() + "." + decodedJWT.getPayload())
					.getBytes(StandardCharsets.US_ASCII);
			return verifier.verify(new JWSHeader(algorithm), signingInput, new Base64URL(decodedJWT.getSignature()));
		} catch (JOSEException e) {
			LOGGER.warn("Signature check of a {} token failed: {}", tokenAlgo, e.getMessage());
			return false;
		}
	}

	/** Tells whether the token is signed with HS384 or HS512. */
	public static boolean isHmacToken(DecodedJWT decodedJWT) {
		String algorithm = decodedJWT.getAlgorithm();
		return HS384_ALGORITHM.equals(algorithm) || HS512_ALGORITHM.equals(algorithm);
	}

	/**
	 * Verifies an HS384 or HS512 token with the configured shared secret, never with a key
	 * from the JWKS endpoint, so that a public key cannot be used as the secret.
	 *
	 * @param secret the shared secret, used as UTF-8 bytes. It must be at least as long as the
	 *               hash output (48 bytes for HS384, 64 for HS512), as RFC 7518 section 3.2 requires.
	 * @return true only if the signature is valid, false for a missing or too short secret
	 */
	public static boolean isHmacSignatureValid(DecodedJWT decodedJWT, String secret) {
		String algorithm = decodedJWT.getAlgorithm();
		boolean hs384 = HS384_ALGORITHM.equals(algorithm);
		if (secret == null || !(hs384 || HS512_ALGORITHM.equals(algorithm))) {
			return false;
		}
		byte[] key = secret.getBytes(StandardCharsets.UTF_8);
		if (key.length < (hs384 ? HS384_MIN_SECRET_LENGTH : HS512_MIN_SECRET_LENGTH)) {
			return false;
		}
		try {
			(hs384 ? Algorithm.HMAC384(key) : Algorithm.HMAC512(key)).verify(decodedJWT);
			return true;
		} catch (SignatureVerificationException e) {
			return false;
		}
	}

	/** Tells whether the token is verified without a {@link PublicKey}: Ed25519, ES256K, HS384 and HS512. */
	public static boolean isVerifiedWithoutPublicKey(DecodedJWT decodedJWT) {
		return isNimbusToken(decodedJWT) || isHmacToken(decodedJWT);
	}

	/** Tells whether a claim exists in the token and is not a JSON null. */
	public static boolean isClaimPresent(Claim claim) {
		return claim != null && !claim.isMissing() && !claim.isNull();
	}

	private static <T extends PublicKey> T keyOfType(PublicKey publicKey, Class<T> keyType, String tokenAlgo) {
		if (publicKey != null && !keyType.isInstance(publicKey)) {
			throw new AlgorithmMismatchException(
					"The public key does not match the token algorithm " + tokenAlgo + ", expected " + keyType.getSimpleName());
		}
		return keyType.cast(publicKey);
	}

	private static final class BouncyCastleHolder {
		private static final Provider PROVIDER = new BouncyCastleProvider();
	}
}
