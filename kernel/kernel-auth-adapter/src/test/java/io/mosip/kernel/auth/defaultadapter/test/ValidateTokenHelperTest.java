package io.mosip.kernel.auth.defaultadapter.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Provider;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestBodyUriSpec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.exception.AuthManagerException;
import io.mosip.kernel.auth.defaultadapter.helper.ValidateTokenHelper;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;
import com.sun.net.httpserver.HttpServer;
import reactor.core.publisher.Mono;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
public class ValidateTokenHelperTest {

	@Autowired
	private ObjectMapper mapper;

	@Value("${auth.server.admin.oidc.certs.path:/protocol/openid-connect/certs}")
	private String certsPath;

	@Value("${auth.server.admin.oidc.userinfo.path:/protocol/openid-connect/userinfo}")
	private String userInfo;

	@Value("${auth.server.admin.issuer.domain.validate:true}")
	private boolean validateIssuerDomain;

	@Value("${auth.server.admin.issuer.uri:}")
	private String issuerURI;

	@Value("${auth.server.admin.issuer.internal.uri:}")
	private String issuerInternalURI;

	@Value("${auth.server.admin.audience.claim.validate:true}")
	private boolean validateAudClaim;

	@Value("#{${mosip.kernel.auth.appids.realm.map}}")
	private Map<String, String> realmMap;

	@Autowired
	private ValidateTokenHelper validateTokenHelper;

	private static final Provider BC = new BouncyCastleProvider();

	private static final String HS384_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";
	private static final String HS512_SECRET = HS384_SECRET + "0123456789abcdef";

	private HttpServer server;

	private RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
	private WebClient webClient = Mockito.mock(WebClient.class);

	@Test
	public void doOnlineTokenValidationTest() throws Exception {
		String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		String userInfoPath = issuerInternalURI + "mosip" + userInfo;
		String resp = "{\r\n" + "  \"error\": \"Forbidden\",\r\n" + "  \"error_description\": \"forbidden\" }";
		when(restTemplate.exchange(Mockito.eq(userInfoPath), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class)))
						.thenThrow(new HttpClientErrorException(HttpStatus.FORBIDDEN, "403", resp.getBytes(),
								Charset.defaultCharset()));
		ImmutablePair<HttpStatus, MosipUserDto> res = validateTokenHelper.doOnlineTokenValidation(token, restTemplate);
		assertNull(res.getValue());
	}

	@Test
	public void doOnlineTokenValidation_withResponseStatusAsOK() throws Exception {
		String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		String userInfoPath = issuerInternalURI + "mosip" + userInfo;
		String resp = "{\r\n" + "  \"error\": \"Forbidden\",\r\n" + "  \"error_description\": \"forbidden\" }";

		when(restTemplate.exchange(Mockito.eq(userInfoPath), Mockito.eq(HttpMethod.GET), Mockito.any(),
				Mockito.eq(String.class))).thenReturn(ResponseEntity.ok("test"));
		ImmutablePair<HttpStatus, MosipUserDto> res = validateTokenHelper.doOnlineTokenValidation(token, restTemplate);
		Assert.assertNotNull(res.getValue());
	}

	@Test
	public void doOnlineTokenValidationWebClientTest() throws Exception {
		String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		String userInfoPath = issuerInternalURI + "mosip" + userInfo;
		RequestBodyUriSpec requestBodyUriSpec = Mockito.mock(RequestBodyUriSpec.class);
		String resp = "{\"access_token\":\"mock-token\"}";
		when(webClient.method(HttpMethod.GET)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.uri(userInfoPath)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.headers(Mockito.any())).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.exchange()).thenReturn(Mono.just(
				ClientResponse.create(HttpStatus.OK).header("Content-type", "application/json").body(resp).build()));
		ImmutablePair<HttpStatus, MosipUserDto> res = validateTokenHelper.doOnlineTokenValidation(token, webClient);
		assertThat(res.getRight().getUserId(), is("service-account-mosip-resident-client"));
	}

	// bug as response is as text not to string
	/*
	 * @Test public void doOnlineTokenValidationWebClientUnAuthTest() throws
	 * Exception { String token=
	 * "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
	 * String userInfoPath = issuerURI + "mosip" + userInfo; RequestBodyUriSpec
	 * requestBodyUriSpec = Mockito.mock(RequestBodyUriSpec.class); String resp =
	 * "{\r\n" + "  \"id\": \"string\", \"version\": \"string\",\r\n" +
	 * "  \"responsetime\": \"2022-01-09T19:38:09.740Z\",\r\n" +
	 * "  \"metadata\": {},\r\n" + "  \"response\": { },\r\n" +
	 * "  \"errors\": [{ \"errorCode\": \"KER-ATH-401\", \"message\": \"unauth\" } ]\r\n"
	 * + "}"; when(webClient.method(HttpMethod.GET)).thenReturn(requestBodyUriSpec);
	 * when(requestBodyUriSpec.uri(userInfoPath)).thenReturn(requestBodyUriSpec);
	 * when(requestBodyUriSpec.headers(Mockito.any())).thenReturn(requestBodyUriSpec
	 * ); when(requestBodyUriSpec.exchange()).thenReturn(Mono.just(ClientResponse.
	 * create(HttpStatus.OK).header("Content-type",
	 * "application/json").body(resp).build())); ImmutablePair<HttpStatus,
	 * MosipUserDto> res
	 * =validateTokenHelper.doOnlineTokenValidation(token,webClient);
	 * assertThat(res.getKey(),is(HttpStatus.UNAUTHORIZED)); }
	 */

	@Test
	public void doOnlineTokenValidationWebClientErrorTest() throws Exception {
		String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		String userInfoPath = issuerInternalURI + "mosip" + userInfo;
		RequestBodyUriSpec requestBodyUriSpec = Mockito.mock(RequestBodyUriSpec.class);
		String resp = "{\"access_token\":\"mock-token\"}";
		when(webClient.method(HttpMethod.GET)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.uri(userInfoPath)).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.headers(Mockito.any())).thenReturn(requestBodyUriSpec);
		when(requestBodyUriSpec.exchange()).thenReturn(Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED)
				.header("Content-type", "application/json").body(resp).build()));
		ImmutablePair<HttpStatus, MosipUserDto> res = validateTokenHelper.doOnlineTokenValidation(token, webClient);
		assertThat(res.getKey(), is(HttpStatus.UNAUTHORIZED));
	}

	@Test(expected = AuthManagerException.class)
	public void doOfflineTokenValidationTest() throws Exception {
		String token = JWT.create().withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.sign(Algorithm.none());

		validateTokenHelper.doOfflineLocalTokenValidation(token);
		//assertThat(validateTokenHelper.doOfflineLocalTokenValidation(token));

	}

	@Test
	public void isTokenValidTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(
				JWT.require(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate())).build()
						.verify(token),
				kp.getPublic());
		assertThat(res.left, is(true));
	}

	@Test
	public void isTokenValid_withRSA384Algo_thenPass() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA384");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" })
				.sign(Algorithm.RSA384((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(
				JWT.require(Algorithm.RSA384((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate())).build()
						.verify(token),
				kp.getPublic());
		assertThat(res.left, is(true));
	}

	@Test
	public void isTokenValid_withRSA512Algo_thenPass() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RS512");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" })
				.sign(Algorithm.RSA512((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(
				JWT.require(Algorithm.RSA512((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate())).build()
						.verify(token),
				kp.getPublic());
		assertThat(res.left, is(true));
	}

	@Test
	public void isTokenInvalidExpiryTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now().minusSeconds(345600)))
				.withExpiresAt(Date.from(Instant.now().minusSeconds(100000))).withAudience(new String[] { "account" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenInvalidIssuerTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://dev.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenInvalidSignatureTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));
		kp = kpg.generateKeyPair();
		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}
	
	@Test
	public void isTokenInvalidAUDTest() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "RSA256");
		String token = JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "abc")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "abc" })
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(
				JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.FORBIDDEN));
	}

	@Test
	public void getPublicKey_withValidDetails_thenPass() throws Exception {
		// Setup: Mock dependencies and prepare the environment
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Map<String, PublicKey> publicKeyMap=new HashMap<>();
		publicKeyMap.put("s6f1p60aeCM0k7-Miol7FboaSuyQboyP-7KTTNeV-fM",kp.getPublic());
		ReflectionTestUtils.setField(validateTokenHelper,"publicKeys",publicKeyMap);
		String jwtToken="eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		DecodedJWT decodedJWT = JWT.decode(jwtToken);

		// Execute
		PublicKey publicKey = validateTokenHelper.getPublicKey(decodedJWT);
		Assert.assertNotNull(publicKey);
		Assert.assertEquals(publicKey,kp.getPublic());
	}


	@Test
	public void getPublicKey_withInValidDetails_thenPass() throws Exception {
		Map<String, PublicKey> publicKeyMap=new HashMap<>();
		ReflectionTestUtils.setField(validateTokenHelper,"publicKeys",publicKeyMap);
		String jwtToken="eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzNmYxcDYwYWVDTTBrNy1NaW9sN0Zib2FTdXlRYm95UC03S1RUTmVWLWZNIn0.eyJqdGkiOiJmYTU4Y2NjMC00ZDRiLTQ2ZjAtYjgwOC0yMWI4ZTdhNmMxNDMiLCJleHAiOjE2NDAxODc3MTksIm5iZiI6MCwiaWF0IjoxNjQwMTUxNzE5LCJpc3MiOiJodHRwczovL2Rldi5tb3NpcC5uZXQva2V5Y2xvYWsvYXV0aC9yZWFsbXMvbW9zaXAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOWRiZTE0MDEtNTQ1NC00OTlhLTlhMWItNzVhZTY4M2Q0MjZhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiY2QwYjU5NjEtOTYzMi00NmE0LWIzMzgtODc4MWEzNDVmMTZiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rldi5tb3NpcC5uZXQiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkNSRURFTlRJQUxfUkVRVUVTVCIsIlJFU0lERU5UIiwib2ZmbGluZV9hY2Nlc3MiLCJQQVJUTkVSX0FETUlOIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtb3NpcC1yZXNpZGVudC1jbGllbnQiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImNsaWVudEhvc3QiOiIxMC4yNDQuNS4xNDgiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoibW9zaXAtcmVzaWRlbnQtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LW1vc2lwLXJlc2lkZW50LWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuNS4xNDgifQ.xZq1m3mBTEvFDENKFOI59QsSl3sd_TSDNbhTAOq4x_x_4voPc4hh08gIxUdsVHfXY4T0P8DdZ1xNt8xd1VWc33Hc4b_3kK7ksGY4wwqtb0-pDLQGajCGuG6vebC1rYcjsGRbJ1Gnrj_F2RNY4Ky6Nq5SAJ1Lh_NVKNKFghAXb3YrlmqlmCB1fCltC4XBqNnF5_k4uzLCu_Wr0lt_M87X97DktaRGLOD2_HY1Ire9YPsWkoO8y7X_DRCY59yQDVgYs2nAiR6Am-c55Q0fEQ0HuB4IJHlhtMHm27dXPdOEhFhR8ZPOyeO6ZIcIm0ZTDjusrruqWy2_yO5fe3XIHkCOAw";
		DecodedJWT decodedJWT = JWT.decode(jwtToken);

		// Execute
		PublicKey publicKey = validateTokenHelper.getPublicKey(decodedJWT);
		Assert.assertNull(publicKey);
	}

	@Test
	public void isTokenValid_withPS256Algo_thenPass() throws Exception {
		KeyPair kp = generateKeyPair("RSA", 2048);
		String token = signedToken(Algorithm.RSA256PSS((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()),
				"PS256");

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(true));
	}

	@Test
	public void isTokenValid_withES256Algo_thenPass() throws Exception {
		KeyPair kp = generateKeyPair("EC", 256);
		String token = signedToken(Algorithm.ECDSA256((ECPublicKey) kp.getPublic(), (ECPrivateKey) kp.getPrivate()),
				"ES256");

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				kp.getPublic());
		assertThat(res.left, is(true));
	}

	@Test
	public void isTokenValid_withPS256TokenAndWrongKey_thenUnauthorized() throws Exception {
		KeyPair kp = generateKeyPair("RSA", 2048);
		KeyPair otherKp = generateKeyPair("RSA", 2048);
		String token = signedToken(Algorithm.RSA256PSS((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()),
				"PS256");

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				otherKp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValid_withES256TokenAndRSAKey_thenUnauthorized() throws Exception {
		KeyPair kp = generateKeyPair("EC", 256);
		KeyPair rsaKp = generateKeyPair("RSA", 2048);
		String token = signedToken(Algorithm.ECDSA256((ECPublicKey) kp.getPublic(), (ECPrivateKey) kp.getPrivate()),
				"ES256");

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = validateTokenHelper.isTokenValid(JWT.decode(token),
				rsaKp.getPublic());
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void buildMosipUser_withRealmAccessClaim_thenRolesFromRealmAccess() throws Exception {
		KeyPair kp = generateKeyPair("RSA", 2048);
		String token = JWT.create().withSubject("mock-user")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.REALM_ACCESS, Collections.singletonMap("roles", Arrays.asList("ADMIN", "RESIDENT")))
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		MosipUserDto user = validateTokenHelper.buildMosipUser(JWT.decode(token), token);

		assertThat(user.getRole(), is("ADMIN,RESIDENT,"));
		assertThat(user.getName(), is("mock-user"));
	}

	@Test
	public void buildMosipUser_withoutRealmAccessClaim_thenRolesFromRolesClaim() throws Exception {
		KeyPair kp = generateKeyPair("RSA", 2048);
		String token = JWT.create().withSubject("mock-user")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN")
				.sign(Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate()));

		MosipUserDto user = validateTokenHelper.buildMosipUser(JWT.decode(token), token);

		assertThat(user.getRole(), is("ADMIN"));
		assertThat(user.getName(), is("mock-user"));
	}

	@Test
	public void isTokenValid_withEd25519Algo_thenPass() throws Exception {
		OctetKeyPair okp = newEd25519Key();

		assertThat(isTokenValidWithKeySet(signedEd25519Token(okp), new JWKSet(okp)).left, is(true));
	}

	@Test
	public void isTokenValid_withES256KAlgo_thenPass() throws Exception {
		ECKey ecKey = newES256KKey();

		assertThat(isTokenValidWithKeySet(signedES256KToken(ecKey), new JWKSet(ecKey)).left, is(true));
	}

	@Test
	public void isTokenValid_withEd25519TokenAndWrongKey_thenUnauthorized() throws Exception {
		OctetKeyPair okp = newEd25519Key();
		OctetKeyPair wrongKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID(okp.getKeyID()).generate();

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithKeySet(signedEd25519Token(okp),
				new JWKSet(wrongKey));
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValid_withES256KTokenAndWrongKey_thenUnauthorized() throws Exception {
		ECKey ecKey = newES256KKey();
		ECKey wrongKey = new ECKeyGenerator(Curve.SECP256K1).provider(BC).keyID(ecKey.getKeyID()).generate();

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithKeySet(signedES256KToken(ecKey),
				new JWKSet(wrongKey));
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValid_withEd25519TokenAndUnknownKeyId_thenUnauthorized() throws Exception {
		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithKeySet(signedEd25519Token(newEd25519Key()),
				new JWKSet(newEd25519Key()));
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValid_withEd25519TokenAndUnreachableCertsEndpoint_thenUnauthorized() throws Exception {
		OctetKeyPair okp = newEd25519Key();
		String token = signedEd25519Token(okp);
		String certsUrlOfStoppedServer = startJwksServer(new JWKSet(okp));
		server.stop(0);

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithCertsUrl(token, certsUrlOfStoppedServer);
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void getPublicKey_withEd25519Token_thenNullWithoutDownloadingKey() throws Exception {
		assertNull(validateTokenHelper.getPublicKey(JWT.decode(signedEd25519Token(newEd25519Key()))));
	}

	@Test
	public void getPublicKey_withES256KToken_thenNullWithoutDownloadingKey() throws Exception {
		assertNull(validateTokenHelper.getPublicKey(JWT.decode(signedES256KToken(newES256KKey()))));
	}

	@Test
	public void isTokenValid_withHS384AndConfiguredSecret_thenPass() {
		assertThat(isTokenValidWithHmacSecret(hmacToken("HS384", HS384_SECRET), HS384_SECRET).left, is(true));
	}

	@Test
	public void isTokenValid_withHS512AndConfiguredSecret_thenPass() {
		assertThat(isTokenValidWithHmacSecret(hmacToken("HS512", HS512_SECRET), HS512_SECRET).left, is(true));
	}

	@Test
	public void isTokenValid_withHS512AndNoConfiguredSecret_thenUnauthorized() {
		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithHmacSecret(hmacToken("HS512", HS512_SECRET), "");
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValid_withHS512AndWrongSecret_thenUnauthorized() {
		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithHmacSecret(hmacToken("HS512", HS512_SECRET),
				HS512_SECRET.replace('0', '9'));
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void isTokenValid_withHS512SignedWithPublicKeyAsSecret_thenUnauthorized() throws Exception {
		KeyPair kp = generateKeyPair("RSA", 2048);
		String forged = JWT.create().withPayload(tokenClaims())
				.sign(Algorithm.HMAC512(Base64.getEncoder().encode(kp.getPublic().getEncoded())));

		ImmutablePair<Boolean, AuthAdapterErrorCode> res = isTokenValidWithHmacSecret(forged, HS512_SECRET);
		assertThat(res.left, is(false));
		assertThat(res.right, is(AuthAdapterErrorCode.UNAUTHORIZED));
	}

	@Test
	public void getPublicKey_withHS512Token_thenNullWithoutDownloadingKey() {
		assertNull(validateTokenHelper.getPublicKey(JWT.decode(hmacToken("HS512", HS512_SECRET))));
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

	@After
	public void stopJwksServer() {
		if (server != null) {
			server.stop(0);
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

	private KeyPair generateKeyPair(String algorithm, int size) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
		if ("EC".equals(algorithm)) {
			kpg.initialize(new ECGenParameterSpec("secp" + size + "r1"));
		} else {
			kpg.initialize(size);
		}
		return kpg.generateKeyPair();
	}

	private String signedToken(Algorithm algorithm, String tokenAlgo) {
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", tokenAlgo);
		return JWT.create().withHeader(headers).withClaim(AuthAdapterConstant.EMAIL, "mockuser!mosip.com")
				.withClaim(AuthAdapterConstant.MOBILE, "9210283991")
				.withClaim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user")
				.withClaim(AuthAdapterConstant.ROLES, "ADMIN").withClaim(AuthAdapterConstant.AZP, "account")
				.withClaim(AuthAdapterConstant.ISSUER, "https://iam.mosip.net/auth/realms/").withSubject("mock-user")
				.withIssuedAt(Date.from(Instant.now())).withExpiresAt(Date.from(Instant.now().plusSeconds(345600)))
				.withAudience(new String[] { "account" }).sign(algorithm);
	}

}
