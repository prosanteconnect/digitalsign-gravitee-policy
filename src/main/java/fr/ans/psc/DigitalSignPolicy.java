package fr.ans.psc;

import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

import fr.ans.psc.esignsante.model.EsignSanteSignatureReport;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.stream.TransformableRequestStreamBuilder;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.resource.api.ResourceManager;

public class DigitalSignPolicy {

    private static final Logger log = LoggerFactory.getLogger(DigitalSignPolicy.class);

    private DigitalSignPolicyConfiguration configuration;

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

    private Function<Buffer, Buffer> sign(ExecutionContext executionContext, DigitalSignPolicyConfiguration configuration, PolicyChain policyChain) {
        return input -> {
            AtomicReference<String> signedDoc = new AtomicReference<>();
            DigitalSignResource<?> signingResource = getDigitalSignResource(executionContext);

            if (signingResource == null) {
                log.error("No Signing resource named {} available", configuration.getResourceName());
                throw new NullPointerException();
            }

            assert signingResource != null;
            signingResource.sign(input.getBytes(), configuration.getAdditionalParameters(), (dgResponse) -> {
                String responseBody = dgResponse.getPayload();
                Gson gson = new Gson();
                EsignSanteSignatureReport report = gson.fromJson(responseBody, EsignSanteSignatureReport.class);
                signedDoc.set(new String(Base64.getDecoder().decode(report.getDocSigne())));
                executionContext.setAttribute("signed.body", new String(Base64.getDecoder().decode(report.getDocSigne())));
            });
            return Buffer.buffer("");
        };
    }
}
