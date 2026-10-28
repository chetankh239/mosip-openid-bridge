package io.mosip.kernel.openid.bridge.api.utils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Provider;
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

public class JWTUtils {
	
	private JWTUtils() {
		
	}

	private static final String ED25519_ALGORITHM = "Ed25519";
	private static final String ES256K_ALGORITHM = "ES256K";
	private static final int JWKS_TIMEOUT_MS = 5000;
	private static final int JWKS_SIZE_LIMIT = 51200;

	private static final Provider BOUNCY_CASTLE = new BouncyCastleProvider();

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
	 * Returns the algorithm used to verify a token signature, based on the
	 * {@code alg} header of the token. Supports RS256/384/512, PS256/384/512 and
	 * ES256/384/512. Any other (or missing) algorithm falls back to RS256.
	 * Ed25519 and ES256K are not supported by java-jwt, see
	 * {@link #isNimbusSignatureValid}.
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
	 * Tells whether the token is signed with an algorithm that java-jwt does not
	 * support (Ed25519 or ES256K). Such tokens are verified with
	 * {@link #isNimbusSignatureValid}.
	 *
	 * @param decodedJWT the decoded token
	 * @return true if the {@code alg} header of the token is Ed25519 or ES256K
	 */
	public static boolean isNimbusToken(DecodedJWT decodedJWT) {
		String algorithm = decodedJWT.getAlgorithm();
		return ED25519_ALGORITHM.equals(algorithm) || ES256K_ALGORITHM.equals(algorithm);
	}

	/**
	 * Reads the public key of a JWKS entry with nimbus-jose-jwt, for the algorithms
	 * java-jwt does not support. The JWKS library used for RSA and EC keys cannot
	 * build OKP keys (Ed25519) or secp256k1 keys (ES256K). Found keys are cached.
	 *
	 * @param certsUrl the JWKS endpoint
	 * @param keyId    the {@code kid} of the key
	 * @return the public key, or null if the endpoint has no key with this id
	 * @throws IOException        if the endpoint cannot be read
	 * @throws ParseException     if the endpoint does not return a valid key set
	 * @throws URISyntaxException if the endpoint is not a valid URI
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
	 * Verifies the signature of an Ed25519 or ES256K token with nimbus-jose-jwt,
	 * because java-jwt does not support these algorithms. Nimbus knows Ed25519 by
	 * its older name EdDSA, which is only used to pick the verifier. The signature
	 * is checked over the original token.
	 *
	 * @param decodedJWT the decoded token
	 * @param publicKey  the public key to verify with
	 * @return true only if the signature is valid. A missing key, a key of the
	 *         wrong type or curve, or an unsupported algorithm give false.
	 */
	public static boolean isNimbusSignatureValid(DecodedJWT decodedJWT, JWK publicKey) {
		try {
			JWSVerifier verifier;
			JWSAlgorithm algorithm;
			if (ED25519_ALGORITHM.equals(decodedJWT.getAlgorithm()) && publicKey instanceof OctetKeyPair octetKeyPair) {
				verifier = new Ed25519Verifier(octetKeyPair);
				algorithm = JWSAlgorithm.EdDSA;
			} else if (ES256K_ALGORITHM.equals(decodedJWT.getAlgorithm()) && publicKey instanceof ECKey ecKey) {
				ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(ecKey);
				// the JDK has no secp256k1 curve
				ecdsaVerifier.getJCAContext().setProvider(BOUNCY_CASTLE);
				verifier = ecdsaVerifier;
				algorithm = JWSAlgorithm.ES256K;
			} else {
				return false;
			}
			byte[] signingInput = (decodedJWT.getHeader() + "." + decodedJWT.getPayload())
					.getBytes(StandardCharsets.US_ASCII);
			return verifier.verify(new JWSHeader(algorithm), signingInput, new Base64URL(decodedJWT.getSignature()));
		} catch (JOSEException e) {
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
