import com.nimbusds.jose.JWSAlgorithm;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.junit.Before;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.openidconnect.model.Constants;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestUtilsTest extends TestCase {

    RSAPrivateKey rsaPrivateKey;
    KeyStore clientKeyStore = null;
    KeyStore clientKeyStoreQA = null;
    KeyStore wso2KeyStore=null;
    String CLIENT_PUBLIC_CERT_ALIAS = "wso2carbon";
    @Before
    public void setUp() throws Exception {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        clientKeyStore =
                getKeyStoreFromFile("HRDevelopmentPrimaryTLS.jks", "2l6ETbHFHqhy",
                        System.getProperty(CarbonBaseConstants.CARBON_HOME));
        clientKeyStoreQA =
                getKeyStoreFromFile("HRQAPrimaryTLS.jks", "hgZ8h3rGqXiKq@",
                        System.getProperty(CarbonBaseConstants.CARBON_HOME));
        wso2KeyStore = getKeyStoreFromFile("wso2carbon.jks", "2l6ETbHFHqhy", System.getProperty(CarbonBaseConstants
                .CARBON_HOME));
    }
    public static KeyStore getKeyStoreFromFile(String keystoreName, String password,
                                               String home) throws Exception {
        Path tenantKeystorePath = Paths.get(home, "repository", "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }


    public void testBuildJWE() {
        String testClientId = "NiEVt57j8OCy4uSSwJ64u53VSzga";
        String audience = "https://localhost:9443/oauth2/token";
        Key privateKey =null;
        Key privateKey2 = null;
        PublicKey publicKey = null;
        PublicKey publicKeyQA = null;
        try {
            rsaPrivateKey = (RSAPrivateKey) wso2KeyStore.getKey("wso2carbon", "2l6ETbHFHqhy".toCharArray());
            privateKey = clientKeyStore.getKey("wso2primarytls", "2l6ETbHFHqhy".toCharArray());
            privateKey2 = wso2KeyStore.getKey("wso2carbon", "2l6ETbHFHqhy".toCharArray());
            publicKey = clientKeyStore.getCertificate("wso2primarytls").getPublicKey();
            publicKeyQA = clientKeyStoreQA.getCertificate("wso2primarytls").getPublicKey();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }



        Map<String, Object> claims1 = new HashMap<>();
        Map<String, Object> claims2 = new HashMap<>();
        Map<String, Object> claims3 = new HashMap<>();
        Map<String, Object> claims4 = new HashMap<>();

        claims1.put(Constants.STATE, "af0ifjsldkj");
        claims1.put(Constants.CLIENT_ID, testClientId);

        JSONObject userInfoClaims = new JSONObject();
        userInfoClaims.put("essential", true);
        userInfoClaims.put("value", "some-value");
        JSONArray valuesArray = new JSONArray();
        valuesArray.add("value1");
        valuesArray.add("value2");
        userInfoClaims.put("values", valuesArray);
        JSONObject userInfoClaim = new JSONObject();
        userInfoClaim.put("user_info", userInfoClaims);
        JSONObject acr = new JSONObject();
        acr.put("acr", userInfoClaim);
        claims2.put("claims", acr);

        claims3.put(Constants.CLIENT_ID, "some-string");

        JSONObject givenName = new JSONObject();
        givenName.put("given_name", null);

        JSONObject idTokenClaim = new JSONObject();
        idTokenClaim.put("id_token", givenName);
        claims4.put("claims", idTokenClaim);

        try {
            String jsonWebToken1 = TestUtils.buildJWT(testClientId, "lakshithas", "1000", audience, "RSA256", privateKey, 0,
                    claims1);
            String jsonWebEncryption1 = TestUtils.buildJWE(testClientId, "lakshithas", "d2bc1aff-4810-44eb-ae76-1d7d98a4d0fa", audience,
                    JWSAlgorithm.NONE.getName(), privateKey, publicKey, 0, claims1);
            String jsonWebEncryption2 = TestUtils.buildJWE(testClientId, "lakshithas", "d2bc1aff-4810-44eb-ae76-1d7d98a4d0fa", audience,
                    JWSAlgorithm.RS256.getName(), privateKey, publicKey, 0, claims1);

           // System.out.println(">>>>>>>>>>>>> JWT with RSA256 "+ jsonWebToken1);
           // System.out.println(">>>>>>>>>>>>> NONE "+ jsonWebEncryption1);
           // System.out.println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<=========>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
           // System.out.println(">>>>>>>>>>>>> RS256 "+ jsonWebEncryption2);

            String encryptString = "eyJ4NXQiOiJOalEzTmpVeFl6TXhaVEU0TURjME1ERmhObVpsWTJGaU5UTTBPRFZoTVdZM01EUmtOR1k1WXpVME5EVXpNVEJsWVRBMk0yUTFOREF5TWprME9UYzFZUSIsImtpZCI6Ik5qUTNOalV4WXpNeFpURTRNRGMwTURGaE5tWmxZMkZpTlRNME9EVmhNV1kzTURSa05HWTVZelUwTkRVek1UQmxZVEEyTTJRMU5EQXlNamswT1RjMVlRX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJsYWtzaGl0aGFzIiwiYXV0IjoiQVBQTElDQVRJT05fVVNFUiIsImF1ZCI6WyJndWhQS1NZRUdsR0pWWXZ5MUpWVmY5ZmZXcklhIiwiaHR0cHM6XC9cL2xvZ2luLXFhLnVuaXR5YnloYXJkcm9jay5jb21cL29hdXRoMlwvdG9rZW4iXSwibmJmIjoxNjIyNzAyMjY3LCJhenAiOiJndWhQS1NZRUdsR0pWWXZ5MUpWVmY5ZmZXcklhIiwic2NvcGUiOiJkZWZhdWx0IiwiaXNzIjoiaHR0cHM6XC9cLzEwLjgwLjQ2LjE0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE2MjI3MDU4NjcsImlhdCI6MTYyMjcwMjI2NywianRpIjoiMTUyOTY1YzYtNjk3Zi00M2JjLThmNTktZmEzMjIxNTcyOWMwIn0.DlCxAcPFEtplggHMRDOuVGgHxiFdLXotaRxx0-qP7Sog8uy9C0KdViWTuQPIWQP-By7W1Zn8n1ToFTHBfYFg5Cfrz3dWhD9ETnA9Dn1xZFItET11M7pTPRBmYZQ5snZJBn5xne2tJdXZD2AsgOJT0UJL58txvCkdt_fQndYUJzOiuRwQ_9pg6WV6JODr8NjNk6OFBNVvvnLUaecjRldPxvszzOdV3VZk-pQhMinmjUzXGEe2wh7cxsP3T1wMzi3MVOJxpfqo7UtM2imE40BaracKUmkzXjMPeBS8KChGGX1nu9xy46VC4U73wk9rTGM1dmyogrRsYVnNbp1JlS4kiw";

            System.out.println(">>>>>>>>>>>>> Test Encryption Local "+ TestUtils.encrypt(encryptString,publicKey));
            System.out.println(">>>>>>>>>>>>> Test Encryption QA "+ TestUtils.encrypt(encryptString,publicKeyQA));

        } catch (RequestObjectException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}