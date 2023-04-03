package com.hoofsandhorns.hrp.hoofgatewayconnector.controllers;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import io.netty.handler.logging.LogLevel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.logging.AdvancedByteBufFormat;

@RestController
public class ReactiveController {
	
	
	private final static URI samlEndpoint = URI.create("https://eproxy1.hr-dev.sberbank.ru:12443/sap/opu/z_saml/ZSB_SAML_MTM/$metadata");
	
	/**
	 * Step 1. 
	 * 
	 * @param cookieStorage
	 * @param client
	 * @param token
	 * @param samlEndpoint
	 * @param locationURI
	 * @see samlRequest
	 * @return
	 */
	@GetMapping("/retrieve-cookies") 
	public Mono<ResponseEntity<String>> retrieve() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException, UnrecoverableKeyException {
		
		ClassLoader classLoader = getClass().getClassLoader();
		InputStream keystoreInputStream = classLoader.getResourceAsStream("ssl/keystore.jks");
		InputStream truststoreInputStream = classLoader.getResourceAsStream("ssl/truststore.jks");
		
		 // create SSL context with keystore and truststore
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(keystoreInputStream, "password".toCharArray());
		
		 // create SSL context with keystore and truststore
		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(truststoreInputStream, "changeit".toCharArray());

		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, "password".toCharArray());

		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(trustStore);

		SslContext sslContext = SslContextBuilder.forClient()
		    .keyManager(keyManagerFactory)
		    .trustManager(trustManagerFactory)
		    .build();
				  
		// create HttpClient with MTLS SSL context
		HttpClient httpClient = HttpClient.create()
			.wiretap("reactor.netty.http.client.HttpClient", LogLevel.INFO, AdvancedByteBufFormat.TEXTUAL)
		    .secure(spec -> spec.sslContext(sslContext));
		
		MultiValueMap<String, String> cookieStorage = new LinkedMultiValueMap<>();
		
		// create WebClient with MTLS SSL HttpClient
		WebClient client = WebClient.builder()
				.clientConnector(new ReactorClientHttpConnector(httpClient))
				.defaultCookies(cookies -> cookies.addAll(cookieStorage))
				.build();
		
		
		String token = "JWT-TOKEN";		
		Mono<ResponseEntity<String>> result = client.get()
				.uri(samlEndpoint)
		        .exchangeToMono(response -> {
		        	if (response.statusCode().is3xxRedirection()) {
			        	saveSessionCookies(cookieStorage, response);
			        	return response.toEntity(String.class);
		        	} else {
		        		// TODO Ошибка
		        		System.out.println("ERROR: " + response.statusCode());
		        		return response.toEntity(String.class);
		        	}
		        })
		        .flatMap(responseFromRedir -> {
		        	URI locationURI = URI.create(responseFromRedir.getHeaders().getFirst("location"));
		        	return samlRequest(cookieStorage, client, token, locationURI);
		        });
		return result;
	}

	/**
	 * Step 2. 
	 * 
	 * @param cookieStorage
	 * @param client
	 * @param token
	 * @param samlEndpoint
	 * @param locationURI
	 * @see retrieve
	 * @return
	 */
	private Mono<ResponseEntity<String>> samlRequest(MultiValueMap<String, String> cookieStorage,
			WebClient client, String token, URI locationURI) {
		return client.get()
				.uri(locationURI)
				.header("Authorization", "Bearer " + token)
				.cookies(cookies -> cookies.addAll(cookieStorage))
				.exchangeToMono(response2 -> {
					if (response2.statusCode().is2xxSuccessful()) {
						saveSessionCookies(cookieStorage, response2);
						System.out.println("Response2: " + cookieStorage);
						return response2.toEntity(String.class);
					} else {
						// TODO Ошибка
						System.out.println("ERROR: " + response2.statusCode());
						return response2.toEntity(String.class);
					}
				})
				.flatMap(response3 -> {
					
		            Document doc = Jsoup.parse(response3.getBody()); // Some string
		            
		    		String location = doc.select("form[name=saml-post-binding]").attr("action");
		    		String samlResponse = doc.select("input[name=SAMLResponse]").attr("value");
		    		String relayState = doc.select("input[name=RelayState]").attr("value");
		    		String encodedSamlResponse = null;
		    		try {
						encodedSamlResponse = URLEncoder.encode(samlResponse, "UTF-8");
					} catch (UnsupportedEncodingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
		    		System.out.println(location);
		    		System.out.println(encodedSamlResponse);
		    		System.out.println(relayState);
					
		    		System.out.println("Response3: " + cookieStorage);
					
					String ascPayload = "SAMLResponse=" + encodedSamlResponse + "&RelayState=" + relayState;
					
					return client.post()
							.uri(location)
		        			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
		        			.body(BodyInserters.fromValue(ascPayload))
		        			.cookies(cookies -> cookies.addAll(cookieStorage))
		        			.exchangeToMono(response4 -> {
		        				
		        				if (response4.statusCode().is2xxSuccessful()) {
		        					
		    						saveSessionCookies(cookieStorage, response4);
		    						
		    						System.out.println("Response4: " + cookieStorage);
		    						return response4.toEntity(String.class);

		        				} else {
		    						// TODO Ошибка
		    						System.out.println("ERROR: " + response4.statusCode());
		    						return response4.toEntity(String.class);
		        				}
		        			})
		        			.flatMap(response5 -> {
		        				
		    					return client.post()
		    							.uri(samlEndpoint)
		    	            			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
		    	            			.body(BodyInserters.fromValue(ascPayload))
		    	            			.cookies(cookies -> cookies.addAll(cookieStorage))
		    	            			.exchangeToMono(response6 -> {
		    	            				
		    	            				if (response6.statusCode().is3xxRedirection()) {
		    	            					
					    						saveSessionCookies(cookieStorage, response6);
					    						
					    						System.out.println("Response6: " + cookieStorage);
					    						return response6.toEntity(String.class);

		    	            				} else {
					    						// TODO Ошибка
					    						System.out.println("ERROR: " + response6.statusCode());
					    						return response6.toEntity(String.class);
		    	            				}
		    	            			})
		    	            			.flatMap(response7 -> {
		    	            				System.out.println("GET VALUE: " + cookieStorage.get("SAP_SESSIONID_HRD_100"));
		    	            				cookieStorage.forEach((key, value) -> {
		    	            					System.out.println("Key= " + key + " : " + "Value=" + value);
		    	            				});
		    	            				
					    					return client.get()
					    							.uri(samlEndpoint)
					    							.accept(MediaType.APPLICATION_JSON)
					    							.cookies(cookies -> cookies.addAll(cookieStorage))
					    							.exchangeToMono(response8 -> {
					    								return response8.toEntity(String.class);
					    							});
					    					
		    	            			});
		        				
		        			});
				});
	}

	/**
	 * Method takes all response cookies from {@link ClientResponse} 
	 * and saves it in temporary cookie storage.
	 * 
	 * @param cookieStorage temporary storage
	 * @param clientResponse response from external server
	 */
	private void saveSessionCookies(MultiValueMap<String, String> cookieStorage, ClientResponse clientResponse) {
		clientResponse.cookies().forEach(
				(responseCookieName, responseCookies) -> 
					cookieStorage.addAll(responseCookieName, 
							responseCookies.stream()
											.map(responseCookie -> responseCookie.getValue())
											.collect(Collectors.toList())));
	}
	
	
}
