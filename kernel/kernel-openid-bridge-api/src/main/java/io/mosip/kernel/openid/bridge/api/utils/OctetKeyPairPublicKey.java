package io.mosip.kernel.openid.bridge.api.utils;

import java.security.PublicKey;

import com.nimbusds.jose.jwk.OctetKeyPair;

/**
 * Public key of type OKP (for example Ed25519), as read from a JWKS endpoint.
 * Nimbus cannot export an OKP key to a {@link PublicKey}, so this wrapper keeps
 * the nimbus key and lets it travel through code that handles
 * {@link PublicKey}.
 */
class OctetKeyPairPublicKey implements PublicKey {

	private static final long serialVersionUID = 1L;

	private final OctetKeyPair octetKeyPair;

	OctetKeyPairPublicKey(OctetKeyPair octetKeyPair) {
		this.octetKeyPair = octetKeyPair.toPublicJWK();
	}

	OctetKeyPair getOctetKeyPair() {
		return octetKeyPair;
	}

	@Override
	public String getAlgorithm() {
		return "EdDSA";
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}
}
