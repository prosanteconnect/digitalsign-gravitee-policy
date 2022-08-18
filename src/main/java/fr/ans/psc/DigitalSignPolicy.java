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
import io.reactivex.rxjava3.core.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class DigitalSignPolicy {

    private static final Logger log = LoggerFactory.getLogger(DigitalSignPolicy.class);

    private DigitalSignPolicyConfiguration configuration;

    public DigitalSignPolicy(DigitalSignPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public Completable onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) throws IOException {

        File docToSignFile = null;
        byte[] docToSignBytes = null;
        try {
            String docToSignAsString = (String) executionContext.getAttribute(configuration.getDocToSignKey());
//            docToSignFile = encapsulateDocToSign(docToSignAsString);
            docToSignBytes = docToSignAsString.getBytes(StandardCharsets.UTF_8);

//            policyChain.doNext(request, response);
        } catch (Exception e) {
            policyChain.failWith(PolicyResult.failure("Something went wrong with doc signing, please contact your administrator"));
        }
        // call resource and get signed doc
        return handleSignature(executionContext, configuration, docToSignBytes, policyChain);
        // put signed doc in gravitee context
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

//    private File encapsulateDocToSign(String docToSign) throws IOException {
//        File docToSignFile = new File("doctosign.txt");
//        BufferedWriter writer = new BufferedWriter(new FileWriter(docToSignFile));
//        writer.write(docToSign);
//        writer.close();
//
//        return docToSignFile;
//    }

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

    private Completable handleSignature(ExecutionContext ctx, DigitalSignPolicyConfiguration configuration, byte[] docToSignBytes, PolicyChain policyChain) {
        DigitalSignResource signingResource = getDigitalSignResource(ctx);
        assert signingResource != null;

        Single<DigitalSignResponse> digitalSignResponse = Single.create(emitter -> signingResource.signWithXmldsig(docToSignBytes, emitter::onSuccess));

        return Completable.fromSingle(digitalSignResponse.doOnSuccess(response -> {
            if (response.isSuccess()) {
                String jsonReport = response.getPayload();
                // TODO extract signed doc
                String signedDoc = "";
                ctx.setAttribute(configuration.getDocToSignKey(), signedDoc);
                policyChain.doNext(ctx.request(), ctx.response());
            } else {
                policyChain.failWith(PolicyResult.failure("Digital Signature failed, please contact your administrator"));
            }
        }));
    }
}