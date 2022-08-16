package fr.ans.psc;

import io.gravitee.policy.api.PolicyConfiguration;

public class DigitalSignPolicyConfiguration implements PolicyConfiguration {

    private String resourceName;

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }
}
