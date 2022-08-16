package fr.ans.psc;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.api.annotations.OnResponse;
import io.gravitee.resource.api.ResourceManager;
import io.reactivex.rxjava3.core.Completable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class DigitalSignPolicy {

    private static final Logger log = LoggerFactory.getLogger(DigitalSignPolicy.class);

    private DigitalSignPolicyConfiguration configuration;

    public DigitalSignPolicy(DigitalSignPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {

        try {
            String docToSignAsString = (String) executionContext.getAttribute("digitalsign.payload");
            File docToSignFile = encapsulateDocToSign(docToSignAsString);


            // getResource

            // call resource and get signed doc
            // put signed doc in gravitee context

            policyChain.doNext(request, response);
        } catch (Exception e) {
            policyChain.failWith(PolicyResult.failure("Something went wrong with doc signing, please contact your administrator"));
        }
    }

    @OnResponse
    public void onResponse(Request request, Response response, PolicyChain policyChain) {
        if (isASuccessfulResponse(response)) {
            policyChain.doNext(request, response);
        } else {
            policyChain.failWith(
                    PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500, "Not a successful response :-("));
        }
    }


    private static boolean isASuccessfulResponse(Response response) {
        switch (response.status() / 100) {
            case 1:
            case 2:
            case 3:
                return true;
            default:
                return false;
        }
    }

    private File encapsulateDocToSign(String docToSign) throws IOException {
        File docToSignFile = new File("doctosign.txt");
        BufferedWriter writer = new BufferedWriter(new FileWriter(docToSignFile));
        writer.write(docToSign);
        writer.close();

        return docToSignFile;
    }


    private DigitalSignResource getDigitalSignResource(ExecutionContext ctx) {

        if (configuration.getResourceName() == null) {
            return null;
        }
        return ctx
                .getComponent(ResourceManager.class)
                .getResource(
                        ctx.getTemplateEngine().getValue(configuration.getResourceName(), String.class),
                        DigitalSignResource.class
                );
    }
}
