package io.mosip.kernel.openid.bridge.api.utils;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Verification only {@link Algorithm} for the RSASSA-PSS based JWS algorithms
 * (PS256, PS384 and PS512), which java-jwt does not provide. Throws
 * {@link SignatureVerificationException} like the other algorithms, so callers
 * can handle it in the same way.
 */
public class PssAlgorithm extends Algorithm {

	private final PublicKey publicKey;
	private final PSSParameterSpec parameters;

	private PssAlgorithm(String name, PSSParameterSpec parameters, PublicKey publicKey) {
		super(name, "RSASSA-PSS using " + parameters.getDigestAlgorithm() + " and MGF1");
		this.publicKey = publicKey;
		this.parameters = parameters;
	}

	public static Algorithm PS256(PublicKey publicKey) {
		return new PssAlgorithm("PS256", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1),
				publicKey);
	}

	public static Algorithm PS384(PublicKey publicKey) {
		return new PssAlgorithm("PS384", new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1),
				publicKey);
	}

	public static Algorithm PS512(PublicKey publicKey) {
		return new PssAlgorithm("PS512", new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1),
				publicKey);
	}

	@Override
	public void verify(DecodedJWT jwt) throws SignatureVerificationException {
		try {
			Signature signature = Signature.getInstance("RSASSA-PSS");
			signature.setParameter(parameters);
			signature.initVerify(publicKey);
			signature.update((jwt.getHeader() + "." + jwt.getPayload()).getBytes(US_ASCII));
			if (!signature.verify(Base64.getUrlDecoder().decode(jwt.getSignature()))) {
				throw new SignatureVerificationException(this);
			}
		} catch (GeneralSecurityException | IllegalArgumentException e) {
			throw new SignatureVerificationException(this, e);
		}
	}

	@Override
	public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
		throw new SignatureGenerationException(this,
				new UnsupportedOperationException("PssAlgorithm can only verify signatures"));
	}
}
