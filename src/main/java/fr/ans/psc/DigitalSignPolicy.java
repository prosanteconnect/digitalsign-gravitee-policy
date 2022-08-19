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
import io.reactivex.rxjava3.disposables.Disposable;
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
    public Disposable onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) throws IOException {

        File docToSignFile = null;
        byte[] docToSignBytes = null;
        try {
            String docToSignAsString = (String) executionContext.getAttribute(configuration.getDocToSignKey());
            // TODO remove debug logs
            System.out.println("doc to sign :");
            System.out.println(docToSignAsString);
            docToSignBytes = docToSignAsString.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            policyChain.failWith(PolicyResult.failure("Something went wrong with doc signing, please contact your administrator"));
        }
        return handleSignature(executionContext, configuration, docToSignBytes, policyChain).subscribe(
                () -> policyChain.doNext(request, response),
                error -> policyChain.failWith(PolicyResult.failure("something wrong happened")));

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

    private DigitalSignResource<?> getDigitalSignResource(ExecutionContext ctx) {

        if (configuration.getResourceName() == null) {
            return null;
        }
        //TODO rm debug log
        System.out.println("configuration.getResourceName = " + configuration.getResourceName());
        System.out.println("template resource = " + ctx.getTemplateEngine().getValue(configuration.getResourceName(), String.class));
        return ctx
                .getComponent(ResourceManager.class)
                .getResource(
                        ctx.getTemplateEngine().getValue(configuration.getResourceName(), String.class),
                        DigitalSignResource.class
                );
    }

    private Completable handleSignature(ExecutionContext ctx, DigitalSignPolicyConfiguration configuration, byte[] docToSignBytes, PolicyChain policyChain) {
        DigitalSignResource<?> signingResource = getDigitalSignResource(ctx);
        //TODO rm debug log
        System.out.println(signingResource == null ? "DIGITAL SIGN RESOURCE IS NULL" : "SIGN RESOURCE IS NOT NULL");
        if (signingResource == null) {
            policyChain.failWith(PolicyResult.failure("No Signing resource named " + configuration.getResourceName() + " available"));
        }

        System.out.println("calling resource...");
        signingResource.signWithXmldsig(docToSignBytes, digitalSignResponse -> {
            System.out.println("result = " + digitalSignResponse.isSuccess());
            System.out.println("rapport de signature :");
            System.out.println(digitalSignResponse.getPayload());
        });
        Single<DigitalSignResponse> digitalSignResponse = Single.create(emitter -> signingResource.signWithXmldsig(docToSignBytes, emitter::onSuccess));

        return Completable.fromSingle(digitalSignResponse.doOnSuccess(response -> {
            if (response.isSuccess()) {
                //TODO rm debug log
                System.out.println("signing successful");
                String jsonReport = response.getPayload();
                // TODO extract signed doc
                String signedDoc = "";
                ctx.setAttribute(configuration.getDocToSignKey(), jsonReport);
                policyChain.doNext(ctx.request(), ctx.response());
            } else {
                //TODO rm debug log
                System.out.println("signing unsuccessful");
                policyChain.failWith(PolicyResult.failure("Digital Signature failed, please contact your administrator"));
            }
        }));
    }
}
