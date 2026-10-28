package io.mosip.kernel.openid.bridge.api.utils;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JWTUtils {
	
	private JWTUtils() {
		
	}

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
	 * ES256/384/512. Any other (or missing) algorithm falls back to RS256.
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
