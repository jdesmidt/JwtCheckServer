package eu.cdinvest.jwtcheck;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.Properties;
import java.io.IOException;

import java.io.FileInputStream;
import java.io.InputStream;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.json.JSONObject;

public class JwtCheck {

	
	public static JwtReturnCode validate(String token, StringBuilder username) {

		String jwkUrl = null;

		try (InputStream input = new FileInputStream("config.properties")) {

            Properties prop = new Properties();
            prop.load(input);
            jwkUrl = prop.getProperty("jwkurl");

			JwtLogger.add("JWK url = " + jwkUrl);

        } catch (IOException ex) {
            ex.printStackTrace();
        }

		try {
			DecodedJWT jwt = JWT.decode(token);

			byte[] textbytes = Base64.getDecoder().decode(jwt.getPayload());
			String text = new String(textbytes);

			JSONObject payload = new JSONObject(text);
			username.setLength(0);
			username.append(payload.getString("sub"));
		
			if( jwt.getExpiresAt().before(new Date())) {
			    return JwtReturnCode.JWT_EXPIRED;
			};
			
			JwkProviderBuilder jb = new JwkProviderBuilder(jwkUrl);
			jb.cached(10, 24, TimeUnit.HOURS);
			JwkProvider provider = jb.build();
			
			Jwk jwk = provider.get(jwt.getKeyId());
			Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
			algorithm.verify(jwt);
			return JwtReturnCode.JWT_VALID;
		} catch (Exception e) {
			JwtLogger.add("Java exception : " + e.getMessage());
			return JwtReturnCode.JWT_INVALID;
		}
	}
}
