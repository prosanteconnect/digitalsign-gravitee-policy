package fr.ans.psc;

import com.google.gson.Gson;
import com.sun.org.apache.xerces.internal.parsers.XMLParser;
import fr.ans.psc.esignsante.model.EsignSanteSignatureReport;
import freemarker.core.OutputFormat;
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
import java.util.Base64;

public class DigitalSignPolicy {

    private static final Logger log = LoggerFactory.getLogger(DigitalSignPolicy.class);

    private final String SIGNED_PREFIX = "signed.";

    private DigitalSignPolicyConfiguration configuration;

    public DigitalSignPolicy(DigitalSignPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public Disposable onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {

        byte[] docToSignBytes = null;
        try {
            String docToSignAsString = (String) executionContext.getAttribute(configuration.getDocToSignKey());
            log.debug(docToSignAsString);
            docToSignBytes = docToSignAsString.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            policyChain.failWith(PolicyResult.failure("Something went wrong with doc signing, please contact your administrator"));
        }
        return handleSignature(executionContext, configuration, docToSignBytes, policyChain).subscribe(
                () -> policyChain.doNext(request, response),
                error -> policyChain.failWith(PolicyResult.failure(error.getMessage()))
        );

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

        return ctx
                .getComponent(ResourceManager.class)
                .getResource(
                        ctx.getTemplateEngine().getValue(configuration.getResourceName(), String.class),
                        DigitalSignResource.class
                );
    }

    private Completable handleSignature(ExecutionContext ctx,
                                        DigitalSignPolicyConfiguration configuration,
                                        byte[] docToSignBytes,
                                        PolicyChain policyChain) {
        DigitalSignResource<?> signingResource = getDigitalSignResource(ctx);

        if (signingResource == null) {
//            return Completable.complete();
            return Single.error(new Throwable("No Signing resource named " + configuration.getResourceName() + " available")).ignoreElement();
//            policyChain.failWith(PolicyResult.failure("No Signing resource named " + configuration.getResourceName() + " available"));
        }

        Single<DigitalSignResponse> digitalSignResponse = Single.create(emitter ->
                signingResource.signWithXmldsig(docToSignBytes, emitter::onSuccess));

        return Completable.fromSingle(digitalSignResponse
                .doOnSuccess(response -> {
                    if (response.isSuccess()) {
                        Gson gson = new Gson();
                        String responseBody = response.getPayload();
                        EsignSanteSignatureReport report = gson.fromJson(responseBody, EsignSanteSignatureReport.class);
                        String signedDoc = new String(Base64.getDecoder().decode(report.getDocSigne()));

                        String signedDocKey = SIGNED_PREFIX + configuration.getDocToSignKey();
                        ctx.setAttribute(signedDocKey, cleanXML(signedDoc));
//                policyChain.doNext(ctx.request(), ctx.response());
                    } else {
                        log.error("Digital Signature failed, please contact your administrator");
                        throw new Throwable("toto");

//                        policyChain.failWith(PolicyResult.failure("Digital Signature failed, please contact your administrator"));
                    }
                }).doOnError(error -> log.error("GRAOU"))
        );
    }

    public static String cleanXML(String xml) {
        if (xml == null) {
            return xml;
        } else {
            return xml.replaceAll("(<!--.*-->)", "").replaceAll(
                    "(<\\?xml.*\\?>)", "");
        }
    }
}
