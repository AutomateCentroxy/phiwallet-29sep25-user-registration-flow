package org.gluu.agama.newuser;

import java.util.HashMap;
import java.util.Map;

import org.gluu.agama.newregistration.JansUserRegistration;



public abstract class NewUserRegistration {
    public abstract Map<String, Object> validateInputs(Map<String, String> profile);

    public abstract String addNewUser(Map<String, String> profile) throws Exception;

    // public abstract boolean usernamePolicyMatch(String userName);

    // public abstract boolean passwordPolicyMatch(String userPassword);

    public abstract String sendEmail(String to, String lang);

    public abstract String sendOTPCode(String phone, String lang);

    public abstract boolean validateOTPCode(String phone, String code);

    public abstract boolean markPhoneAsVerified(String userName, String phone);
    
    // public static UserRegistration getInstance(){
    //     return  JansUserRegistration.getInstance();
    // } 
    
    public static NewUserRegistration getInstance(HashMap config) {
        return new JansUserRegistration(config);
    }
}
