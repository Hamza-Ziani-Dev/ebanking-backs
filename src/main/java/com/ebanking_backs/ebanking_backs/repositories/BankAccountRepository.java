package com.ebanking_backs.ebanking_backs.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ebanking_backs.ebanking_backs.entities.BankAccount;

public interface BankAccountRepository extends JpaRepository<BankAccount,String> {

    BankAccount findBankAccountById(String accountId);


}