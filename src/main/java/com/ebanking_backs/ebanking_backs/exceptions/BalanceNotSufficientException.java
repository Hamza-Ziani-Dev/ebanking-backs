package com.ebanking_backs.ebanking_backs.exceptions;


public class BalanceNotSufficientException extends Exception {
    public BalanceNotSufficientException(String message) {
        super(message);
    }
}