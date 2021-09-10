import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;


public class TestUtils {

    public static String buildJWT(String issuer, String subject, String jti, String audience, String algorythm,
                                  Key privateKey, long notBeforeMillis, Map<String, Object> claims)
            throws RequestObjectException {
        long lifetimeInMillis = 3600 * 1000;
        return buildJWTWithExpiry(issuer, subject, jti, audience, algorythm, privateKey, notBeforeMillis, claims,
                lifetimeInMillis);
    }

    public static String buildJWE(String issuer, String subject, String jti, String audience, String algorithm,
                                  Key privateKey, Key publicKey, long notBeforeMillis,
                                  Map<String, Object> claims) throws RequestObjectException {
        long lifetimeInMillis = 3600 * 1000;
        JWTClaimsSet jwtClaimsSet = getJwtClaimsSet(issuer, subject, jti, audience, notBeforeMillis, claims,
                lifetimeInMillis);

        if (JWSAlgorithm.NONE.getName().equals(algorithm)) {
            return getEncryptedJWT((RSAPublicKey) publicKey, jwtClaimsSet);
        } else {
            return getSignedAndEncryptedJWT(publicKey, (RSAPrivateKey) privateKey, jwtClaimsSet);
        }
    }

    private static JWTClaimsSet getJwtClaimsSet(String issuer, String subject, String jti, String audience, long
            notBeforeMillis, Map<String, Object> claims, long lifetimeInMillis) {

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        // Set claims to jwt token.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.claim("aut","APPLICATION_USER");
        jwtClaimsSetBuilder.claim("scope","openid");
        jwtClaimsSetBuilder.subject(subject);
        List<String> lst = new ArrayList<>();
        lst.add("NiEVt57j8OCy4uSSwJ64u53VSzga");
        lst.add(audience);
        lst.add("test");
        jwtClaimsSetBuilder.audience(lst);
        jwtClaimsSetBuilder.jwtID(jti);
        jwtClaimsSetBuilder.expirationTime(new Date((curTimeInMillis + lifetimeInMillis)));
        jwtClaimsSetBuilder.issueTime(new Date(curTimeInMillis));

        if (notBeforeMillis > 0) {
            jwtClaimsSetBuilder.notBeforeTime(new Date(curTimeInMillis + notBeforeMillis));
        }
        if (claims != null && !claims.isEmpty()) {
            for (Map.Entry entry : claims.entrySet()) {
                jwtClaimsSetBuilder.claim(entry.getKey().toString(), entry.getValue());
            }
        }
        return jwtClaimsSetBuilder.build();
    }

    private static String getEncryptedJWT(RSAPublicKey publicKey, JWTClaimsSet jwtClaimsSet) throws
            RequestObjectException {
        // Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

        // Create the encrypted JWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaimsSet);

        try {
            // Create an encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(publicKey);
            // Do the actual encryption
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new RequestObjectException("error_building_jwd", "Error occurred while creating JWE JWT.");

        }
        return jwt.serialize();
    }

    private static String getSignedAndEncryptedJWT(Key publicKey, RSAPrivateKey privateKey,
                                                   JWTClaimsSet jwtClaimsSet) throws RequestObjectException {
        SignedJWT signedJWT = getSignedJWT(jwtClaimsSet, privateKey);
        // Create JWE object with signed JWT as payload
        JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(signedJWT.serialize()));
        // Perform encryption
        try {
            jweObject.encrypt(new RSAEncrypter((RSAPublicKey) publicKey));
            return jweObject.serialize();
        } catch (JOSEException e) {
            throw new RequestObjectException("error_building_jwd", "Error occurred while creating JWE.");
        }
    }

    private static SignedJWT getSignedJWT(JWTClaimsSet jwtClaimsSet, RSAPrivateKey privateKey)
            throws RequestObjectException {

        try {
            JWSSigner signer = new RSASSASigner(privateKey);
            JWSHeader.Builder builder =   new JWSHeader.Builder(new JWSHeader(JWSAlgorithm.RS256)).keyID("MTQ1MDY3MDNmOWYzMDgwZDRjMjBhY2I1MWFmN2Q2YzNjOWFjNzMyMzcyMTYzMWVkY2E1MjRlYzdlZTg0NzJiOA_RS256");
            builder.x509CertSHA256Thumbprint(new Base64URL("MTQ1MDY3MDNmOWYzMDgwZDRjMjBhY2I1MWFmN2Q2YzNjOWFjNzMyMzcyMTYzMWVkY2E1MjRlYzdlZTg0NzJiOA"));
            JWSHeader header = builder.build();
           // JWSHeader header = new JWSHeader(JWSAlgorithm.RS256,null,null,null,null,null,null,null,null,null,"MTQ1MDY3MDNmOWYzMDgwZDRjMjBhY2I1MWFmN2Q2YzNjOWFjNzMyMzcyMTYzMWVkY2E1MjRlYzdlZTg0NzJiOA_RS256",null,null);
            SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw new RequestObjectException("error_signing_jwt", "Error occurred while signing JWT.");
        }
    }

    public static String buildJWTWithExpiry(String issuer, String subject, String jti, String audience, String
            algorithm, Key privateKey, long notBeforeMillis, Map<String, Object> claims, long lifetimeInMillis)
            throws RequestObjectException {

        JWTClaimsSet jwtClaimsSet = getJwtClaimsSet(issuer, subject, jti, audience, notBeforeMillis, claims,
                lifetimeInMillis);
        if (JWSAlgorithm.NONE.getName().equals(algorithm)) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWTWithRSA(jwtClaimsSet, privateKey);
    }

    public static String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, Key privateKey)
            throws RequestObjectException {
        SignedJWT signedJWT = getSignedJWT(jwtClaimsSet, (RSAPrivateKey) privateKey);
        return signedJWT.serialize();
    }

    public static String encrypt(String plainToken, PublicKey publicKey) throws Exception {

        SignedJWT signedJWT = SignedJWT.parse(plainToken);
        // Create JWE object with signed JWT as payload
        JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(signedJWT.serialize()));
        // Perform encryption
        jweObject.encrypt(new RSAEncrypter((RSAPublicKey) publicKey));
        return jweObject.serialize();

    }

}
