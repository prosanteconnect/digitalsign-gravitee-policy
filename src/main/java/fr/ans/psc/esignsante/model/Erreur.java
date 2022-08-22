package fr.ans.psc.esignsante.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Erreur {

    @JsonProperty
    private String codeErreur;

    @JsonProperty
    private String message;

    public String getCodeErreur() {
        return codeErreur;
    }

    public void setCodeErreur(String codeErreur) {
        this.codeErreur = codeErreur;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
