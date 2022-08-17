package fr.ans.psc;

import io.gravitee.policy.api.PolicyConfiguration;

public class DigitalSignPolicyConfiguration implements PolicyConfiguration {

    private String resourceName;

    private String docToSignKey;

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public String getDocToSignKey() {
        return docToSignKey;
    }

    public void setDocToSignKey(String docToSignKey) {
        this.docToSignKey = docToSignKey;
    }
}
