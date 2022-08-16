package fr.ans.psc;

import io.gravitee.policy.api.PolicyConfiguration;

public class DigitalSignPolicyConfiguration implements PolicyConfiguration {

    private String resourceName;

    private String docToSignRef;

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public String getDocToSignRef() {
        return docToSignRef;
    }

    public void setDocToSignRef(String docToSignRef) {
        this.docToSignRef = docToSignRef;
    }
}
