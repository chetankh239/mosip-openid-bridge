package io.mosip.kernel.openid.bridge.api.utils;

import java.text.ParseException;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.Ed25519Verifier;

/**
 * Verification only EdDSA algorithm. java-jwt has no EdDSA support, so the
 * signature is checked by nimbus-jose-jwt. It throws
 * {@link SignatureVerificationException} like the java-jwt algorithms, so the
 * existing error handling is unchanged.
 */
class EdDSAAlgorithm extends Algorithm {

	private final OctetKeyPairPublicKey publicKey;

	EdDSAAlgorithm(OctetKeyPairPublicKey publicKey) {
		super("EdDSA", "EdDSA");
		this.publicKey = publicKey;
	}

	@Override
	public void verify(DecodedJWT jwt) throws SignatureVerificationException {
		if (publicKey == null) {
			throw new SignatureVerificationException(this);
		}
		try {
			if (!JWSObject.parse(jwt.getToken()).verify(new Ed25519Verifier(publicKey.getOctetKeyPair()))) {
				throw new SignatureVerificationException(this);
			}
		} catch (ParseException | JOSEException e) {
			throw new SignatureVerificationException(this, e);
		}
	}

	@Override
	public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
		throw new SignatureGenerationException(this, new UnsupportedOperationException("Signing is not supported"));
	}
}
