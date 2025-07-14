package org.joget.marketplace;

import io.jsonwebtoken.Jwts;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppService;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.dao.FormDataDao;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.model.FormRowSet;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.UuidGenerator;
import org.joget.directory.model.User;
import org.joget.plugin.base.ExtDefaultPlugin;
import org.joget.plugin.base.PluginWebSupport;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class JwtSsoWebService extends ExtDefaultPlugin implements PluginWebSupport {

    public static String MESSAGE_PATH = "messages/JwtSsoWebService";
    public static Long JWT_TTL = 1 * 60 * 1000L;

    public static String COOKIE_REDIRECT = "jssor";
    public static int COOKIE_MAX_AGE = 60 * 60;

    public static String APP_ID = "jwtsso";

    @Override
    public String getName() {
        return getMessage("jsw.name");
    }

    @Override
    public String getVersion() {
        return getMessage("jsw.version");
    }

    @Override
    public String getDescription() {
        return getMessage("jsw.desc");
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        LogUtil.info(getClass().getName(), request.getRequestURL().toString());

        //check appId
        /*
        AppDefinition appDef = AppUtil.getCurrentAppDefinition();
        if(appDef == null || !appDef.getAppId().equalsIgnoreCase(APP_ID)) {
            LogUtil.info(getClass().getName(), "appId missing");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        */

        AppService appService = (AppService) AppUtil.getApplicationContext().getBean("appService");
        FormDataDao formDataDao = (FormDataDao) AppUtil.getApplicationContext().getBean("formDataDao");
        AppDefinition appDef = appService.getAppDefinition(APP_ID, null);

        //check param
        String clientId = request.getParameter("clientId");
        String redirect = request.getParameter("redirect");

        if(clientId == null || clientId.isEmpty()){
            LogUtil.info(getClass().getName(), "clientId is missing");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        FormRowSet rows = formDataDao.find("client", "jwtsso_client", "WHERE e.customProperties.client_id = ?", new String[]{clientId}, null, null, null, null);
        if(rows == null || rows.size() == 0){
            LogUtil.info(getClass().getName(), "no rows with clientId " + clientId + " found");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        FormRow row = rows.get(0);

        //validation
        String active = row.getProperty("active");
        if(active == null || active.isEmpty() || active.equalsIgnoreCase("no") || active.equalsIgnoreCase("false")){
            LogUtil.info(getClass().getName(), "client is not active");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        if(WorkflowUtil.isCurrentUserAnonymous()){
            LogUtil.info(getClass().getName(), "is not logged in, redirecting to login page");

            new HttpSessionRequestCache().saveRequest(request, response);

            String url = request.getContextPath() + "/web/userview/" + APP_ID + "/v/_/jwtsso?embed=true&clientId=" + clientId + "&redirect=" + redirect;

            Cookie cookie = new Cookie(COOKIE_REDIRECT, url);
            cookie.setPath(request.getContextPath());
            cookie.setMaxAge(COOKIE_MAX_AGE);
            response.addCookie(cookie);
            response.sendRedirect(url);

        }else{
            LogUtil.info(getClass().getName(), "is logged in, generating jwt");

            WorkflowUserManager workflowUserManager = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
            User user = workflowUserManager.getCurrentUser();

            long expMillis = System.currentTimeMillis() + JWT_TTL;
            Date exp = new Date(expMillis);

            PrivateKey privateKey = loadPrivateKey(row.getProperty("private_key"));
            PublicKey publicKey = loadPublicKey(row.getProperty("public_key"));

            if(privateKey == null || publicKey == null){
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }

            /*
            KeyPair keyPair = Jwts.SIG.RS256.keyPair().build();

            generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            LogUtil.info(getClass().getName(), "privatekey: " + privateKey);
            LogUtil.info(getClass().getName(), "privatekey: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            LogUtil.info(getClass().getName(), "privatekey: " + privateKey.getFormat());
            LogUtil.info(getClass().getName(), "privatekey: " + privateKey.getAlgorithm());
            LogUtil.info(getClass().getName(), "publickey : " + publicKey);
            LogUtil.info(getClass().getName(), "publickey : " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            LogUtil.info(getClass().getName(), "publickey : " + publicKey.getFormat());
            LogUtil.info(getClass().getName(), "publickey : " + publicKey.getAlgorithm());
            */

            String jws = Jwts.builder()
                    .id(UuidGenerator.getInstance().getUuid())
                    .issuer("Joget")
                    .subject("sso")
                    .claim("username", user.getUsername())
                    .claim("email", user.getEmail())
                    .claim("firstName", user.getFirstName())
                    .claim("lastName", user.getLastName())
                    .issuedAt(new Date())
                    .expiration(exp)
                    //.signWith(Keys.hmacShaKeyFor("ymKRak7xa1awUtfZt3Ib8d70X2cFnsNP".getBytes()))
                    .signWith(privateKey)
                    .compact();

            LogUtil.info(getClass().getName(), "jwt: " + jws);

            String callbackUrl = rows.get(0).getProperty("callback_url") + "?jwt=" + jws;

            LogUtil.info(getClass().getName(), "redirecting to " + callbackUrl);
            response.sendRedirect(callbackUrl);
        }
    }

    protected String getMessage(String key) {
        return AppPluginUtil.getMessage(key, getClass().getName(), MESSAGE_PATH);
    }

    protected PrivateKey loadPrivateKey(String privateKeyString) {
        PrivateKey pvt = null;
        try {
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pvt = kf.generatePrivate(ks);
        } catch (Exception e) {
            LogUtil.info(getClass().getName(), "error loading private key: " + e.getMessage());
        }

        return pvt;
    }

    protected PublicKey loadPublicKey(String publicKeyString) {
        PublicKey pub = null;
        try {
            X509EncodedKeySpec ks = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub = kf.generatePublic(ks);
        } catch (Exception e) {
            LogUtil.info(getClass().getName(), "error loading public key: " + e.getMessage());
        }
        return pub;
    }
}
