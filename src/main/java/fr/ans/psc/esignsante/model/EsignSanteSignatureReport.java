package fr.ans.psc.esignsante.model;


import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class EsignSanteSignatureReport {

    @JsonProperty
    private List<Erreur> erreurs;

    @JsonProperty
    private String docSigne;

    public List<Erreur> getErreurs() {
        return erreurs;
    }

    public void setErreurs(List<Erreur> erreurs) {
        this.erreurs = erreurs;
    }

    public String getDocSigne() {
        return docSigne;
    }

    public void setDocSigne(String docSigne) {
        this.docSigne = docSigne;
    }
}
