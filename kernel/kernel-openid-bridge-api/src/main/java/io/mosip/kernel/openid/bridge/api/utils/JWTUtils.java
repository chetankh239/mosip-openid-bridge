package io.mosip.kernel.openid.bridge.api.utils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
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
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;

public class JWTUtils {
	
	private JWTUtils() {
		
	}

	private static final String EDDSA_ALGORITHM = "EdDSA";
	private static final int JWKS_TIMEOUT_MS = 5000;
	private static final int JWKS_SIZE_LIMIT = 51200;

	private static final Map<String, OctetKeyPair> octetKeyPairCache = new ConcurrentHashMap<>();

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
	 * Returns the algorithm used to verify a token signature, based on the
	 * {@code alg} header of the token. Supports RS256/384/512, PS256/384/512 and
	 * ES256/384/512. Any other (or missing) algorithm falls back to RS256. EdDSA is
	 * not supported by java-jwt, see {@link #isEdDSASignatureValid}.
	 *
	 * @param tokenAlgo the {@code alg} header value of the token
	 * @param publicKey the public key used to verify the signature
	 * @return the verification algorithm
	 * @throws AlgorithmMismatchException if the key type does not match the
	 *                                    algorithm, for example an EC key for an
	 *                                    RS256 token
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

	/**
	 * Tells whether the token is signed with EdDSA, which java-jwt does not
	 * support. Such tokens are verified with {@link #isEdDSASignatureValid}.
	 *
	 * @param decodedJWT the decoded token
	 * @return true if the {@code alg} header of the token is EdDSA
	 */
	public static boolean isEdDSAToken(DecodedJWT decodedJWT) {
		return EDDSA_ALGORITHM.equals(decodedJWT.getAlgorithm());
	}

	/**
	 * Reads an OKP key (for example Ed25519) from a JWKS endpoint with
	 * nimbus-jose-jwt, because the JWKS library used for RSA and EC keys cannot
	 * build OKP keys. Found keys are cached.
	 *
	 * @param certsUrl the JWKS endpoint
	 * @param keyId    the {@code kid} of the key
	 * @return the public key, or null if the endpoint has no OKP key with this id
	 * @throws IOException        if the endpoint cannot be read
	 * @throws ParseException     if the endpoint does not return a valid key set
	 * @throws URISyntaxException if the endpoint is not a valid URI
	 */
	public static OctetKeyPair getOctetKeyPair(String certsUrl, String keyId)
			throws IOException, ParseException, URISyntaxException {
		String cacheKey = certsUrl + "#" + keyId;
		OctetKeyPair publicKey = octetKeyPairCache.get(cacheKey);
		if (publicKey == null) {
			JWK jwk = JWKSet.load(new URI(certsUrl).normalize().toURL(), JWKS_TIMEOUT_MS, JWKS_TIMEOUT_MS,
					JWKS_SIZE_LIMIT).getKeyByKeyId(keyId);
			if (jwk instanceof OctetKeyPair octetKeyPair) {
				publicKey = octetKeyPair.toPublicJWK();
				octetKeyPairCache.put(cacheKey, publicKey);
			}
		}
		return publicKey;
	}

	/**
	 * Verifies the signature of an EdDSA token with nimbus-jose-jwt, because
	 * java-jwt does not support EdDSA.
	 *
	 * @param decodedJWT the decoded token
	 * @param publicKey  the public key to verify with
	 * @return true only if the signature is valid. A missing key, a key that is
	 *         not Ed25519 or a malformed token give false.
	 */
	public static boolean isEdDSASignatureValid(DecodedJWT decodedJWT, OctetKeyPair publicKey) {
		if (publicKey == null) {
			return false;
		}
		try {
			return JWSObject.parse(decodedJWT.getToken()).verify(new Ed25519Verifier(publicKey));
		} catch (ParseException | JOSEException e) {
			return false;
		}
	}

	/**
	 * Tells whether a token claim has a value. A claim that is absent from the
	 * token, or present with a JSON null, has no value.
	 *
	 * @param claim the claim read from the token
	 * @return true if the claim has a value
	 */
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
}
