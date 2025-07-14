package org.joget.marketplace;

import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppService;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.FormRow;
import org.joget.apps.form.model.FormRowSet;
import org.joget.commons.util.LogUtil;
import org.joget.plugin.base.DefaultApplicationPlugin;
import org.joget.workflow.model.WorkflowAssignment;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;

public class JwtKeyGeneratorTool extends DefaultApplicationPlugin {

    public static String MESSAGE_PATH = "messages/JwtKeyGeneratorTool";

    @Override
    public String getName() {
        return getMessage("jskg.name");
    }

    @Override
    public String getVersion() {
        return getMessage("jskg.version");
    }

    @Override
    public String getDescription() {
        return getMessage("jskg.desc");
    }

    @Override
    public String getLabel() {
        return getMessage("jskg.label");
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClass().getName(), "/properties/JwtKeyGeneratorTool.json", null, true, MESSAGE_PATH);
    }

    @Override
    public Object execute(Map properties) {
        AppDefinition appDef = AppUtil.getCurrentAppDefinition();

        //String id = "#form.jwtsso_client.id#";
        //String formDefId = "client";

        AppService appService = (AppService) AppUtil.getApplicationContext().getBean("appService");

        WorkflowAssignment wfAssignment = (WorkflowAssignment) properties.get("workflowAssignment");
        String formDefId = getPropertyString("formDefId");
        String publicKeyFieldId = getPropertyString("publicKeyFieldId");
        String privateKeyFieldId = getPropertyString("privateKeyFieldId");
        String recordId = getPropertyString("recordId");

        if(recordId == null || recordId.isEmpty()){
            recordId = (String) properties.get("recordId");
            if(recordId == null || recordId.isEmpty()){
                recordId = appService.getOriginProcessId(wfAssignment.getProcessId());
            }
        }

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            FormRow row = new FormRow();
            FormRowSet rowSet = appService.loadFormData(appDef.getAppId(), appDef.getVersion().toString(), formDefId, recordId);
            if (!rowSet.isEmpty()) {
                row = rowSet.get(0);
                row.setProperty(privateKeyFieldId, Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
                row.setProperty(publicKeyFieldId, Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            }

            rowSet.set(0, row);
            appService.storeFormData(appDef.getAppId(), appDef.getVersion().toString(), formDefId, rowSet, recordId);
        } catch (Exception e) {
            LogUtil.error(getClassName(), e, "error generating public/private keys");
        }

        return null;
    }

    protected String getMessage(String key) {
        return AppPluginUtil.getMessage(key, getClass().getName(), MESSAGE_PATH);
    }
}
