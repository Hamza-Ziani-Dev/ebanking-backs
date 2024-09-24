package com.ebanking_backs.ebanking_backs.exceptions;


public class BankAccountNotFoundException extends Exception {
    public BankAccountNotFoundException(String message) {
        super(message);
    }
}
