package fr.ans.psc;

import io.gravitee.policy.api.PolicyConfiguration;

import java.util.List;

public class DigitalSignPolicyConfiguration implements PolicyConfiguration {

    private String resourceName;

    private String docToSignKey;

    private List<AdditionalParameter> additionalParameters;

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

    public List<AdditionalParameter> getAdditionalParameters() {
        return additionalParameters;
    }

    public void setAdditionalParameters(List<AdditionalParameter> additionalParameters) {
        this.additionalParameters = additionalParameters;
    }
}
