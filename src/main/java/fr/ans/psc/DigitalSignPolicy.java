package fr.ans.psc;

import com.google.gson.Gson;
import fr.ans.psc.esignsante.model.EsignSanteSignatureReport;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.stream.TransformableRequestStreamBuilder;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.api.annotations.OnResponse;
import io.gravitee.resource.api.ResourceManager;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

public class DigitalSignPolicy {

    private static final Logger log = LoggerFactory.getLogger(DigitalSignPolicy.class);

    private final String SIGNED_PREFIX = "signed.";

    private DigitalSignPolicyConfiguration configuration;

    private ByteArrayOutputStream baos;

    public DigitalSignPolicy(DigitalSignPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequestContent
    public ReadWriteStream onRequestContent(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {

        return TransformableRequestStreamBuilder
                .on(request)
                .chain(policyChain)
                .contentType(MediaType.APPLICATION_XML)
                .transform(sign(executionContext, configuration, policyChain))
                .build();

//        String docToSignAsString = executionContext.getTemplateEngine().getValue(configuration.getDocToSignKey(), String.class);
//        String docToSignAsString = (String) executionContext.getTemplateEngine().getTemplateContext().lookupVariable(configuration.getDocToSignKey());
//
//        log.error("docToSignKey : {}", configuration.getDocToSignKey());
//        log.error("docToSignAsString : {}", docToSignAsString);
//
//        byte[] docToSignBytes = docToSignAsString.getBytes(StandardCharsets.UTF_8);
//        return handleSignature(executionContext, configuration, docToSignBytes).subscribe(
//                () -> policyChain.doNext(request, response),
//                error -> policyChain.failWith(PolicyResult.failure("Digital Signature failed, please contact your administrator"))
//        );
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
                                        byte[] docToSignBytes) {
        DigitalSignResource<?> signingResource = getDigitalSignResource(ctx);

        if (signingResource == null) {
            log.error("No Signing resource named {} available", configuration.getResourceName());
            return Single.error(new Error()).ignoreElement();
        }

        Single<DigitalSignResponse> digitalSignResponse = Single.create(emitter ->
                signingResource.sign(docToSignBytes, configuration.getAdditionalParameters(), emitter::onSuccess));

        return Completable.fromSingle(digitalSignResponse
                .doOnSuccess(response -> {
                    if (response.isSuccess()) {
                        Gson gson = new Gson();
                        String responseBody = response.getPayload();
                        EsignSanteSignatureReport report = gson.fromJson(responseBody, EsignSanteSignatureReport.class);
                        String signedDoc = new String(Base64.getDecoder().decode(report.getDocSigne()));

                        String signedDocKey = SIGNED_PREFIX + configuration.getDocToSignKey();
                        log.error("signed.vihf.token.payload");
                        log.error(signedDoc);
                        ctx.setAttribute(signedDocKey, signedDoc);
                    } else {
                        log.error("Signature server has rejected request");
                        throw new Error();
                    }
                })
        );
    }

    private Function<Buffer, Buffer> sign(ExecutionContext executionContext, DigitalSignPolicyConfiguration configuration, PolicyChain policyChain) {
        return input -> {
            AtomicReference<String> signedDoc = new AtomicReference<>();
            DigitalSignResource<?> signingResource = getDigitalSignResource(executionContext);

            if (signingResource == null) {
                log.error("No Signing resource named {} available", configuration.getResourceName());
//                return Single.error(new Error()).ignoreElement();
            }

            assert signingResource != null;
            signingResource.sign(input.getBytes(), configuration.getAdditionalParameters(), (dgResponse) -> {
                String responseBody = dgResponse.getPayload();
                Gson gson = new Gson();
                EsignSanteSignatureReport report = gson.fromJson(responseBody, EsignSanteSignatureReport.class);
//                signedDoc.set(new String(Base64.getDecoder().decode(report.getDocSigne())));
                baos = new ByteArrayOutputStream(Base64.getDecoder().decode(report.getDocSigne()).length);
                try {
                    baos.write(Base64.getDecoder().decode(report.getDocSigne()));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            return Buffer.buffer(baos.toString());
        };
    }
}
