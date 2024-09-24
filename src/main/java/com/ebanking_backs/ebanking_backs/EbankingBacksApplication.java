package com.ebanking_backs.ebanking_backs;

import java.sql.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.ebanking_backs.ebanking_backs.entities.AccountOperation;
import com.ebanking_backs.ebanking_backs.entities.CurrentAccount;
import com.ebanking_backs.ebanking_backs.entities.Customer;
import com.ebanking_backs.ebanking_backs.entities.SavingAccount;
import com.ebanking_backs.ebanking_backs.enums.AccountStatus;
import com.ebanking_backs.ebanking_backs.enums.OperationType;

import com.ebanking_backs.ebanking_backs.repositories.AccountOperationRepository;
import com.ebanking_backs.ebanking_backs.repositories.BankAccountRepository;
import com.ebanking_backs.ebanking_backs.repositories.CustomerRepository;
import com.ebanking_backs.ebanking_backs.services.BankAccountService;
import com.ebanking_backs.ebanking_backs.exceptions.CustomerNotFoundException;
import com.ebanking_backs.ebanking_backs.dtos.BankAccountDTO;
import com.ebanking_backs.ebanking_backs.dtos.CurrentBankAccountDTO;
import com.ebanking_backs.ebanking_backs.dtos.CustomerDTO;
import com.ebanking_backs.ebanking_backs.dtos.SavingBankAccountDTO;

@SpringBootApplication
public class EbankingBacksApplication {

	public static void main(String[] args) {
		SpringApplication.run(EbankingBacksApplication.class, args);
	}


    @Bean
    CommandLineRunner commandLineRunner(BankAccountService bankAccountService){
        return args -> {
           Stream.of("Hassan","Imane","Mohamed").forEach(name->{
               CustomerDTO customer=new CustomerDTO();
               customer.setName(name);
               customer.setEmail(name+"@gmail.com");
               bankAccountService.saveCustomer(customer);
           });
           bankAccountService.listCustomers().forEach(customer->{
               try {
                   bankAccountService.saveCurrentBankAccount(Math.random()*90000,9000,customer.getId());
                   bankAccountService.saveSavingBankAccount(Math.random()*120000,5.5,customer.getId());

               } catch (CustomerNotFoundException e) {
                   e.printStackTrace();
               }
           });
            List<BankAccountDTO> bankAccounts = bankAccountService.bankAccountList();
            for (BankAccountDTO bankAccount:bankAccounts){
                for (int i = 0; i <10 ; i++) {
                    String accountId;
                    if(bankAccount instanceof SavingBankAccountDTO){
                        accountId=((SavingBankAccountDTO) bankAccount).getId();
                    } else{
                        accountId=((CurrentBankAccountDTO) bankAccount).getId();
                    }
                    bankAccountService.credit(accountId,10000+Math.random()*120000,"Credit");
                    bankAccountService.debit(accountId,1000+Math.random()*9000,"Debit");
                }
            }
        };
    }
	// @Bean
    CommandLineRunner start(CustomerRepository customerRepository,
							BankAccountRepository bankAccountRepository,
							AccountOperationRepository accountOperationRepository) {

		return args -> {
			Stream.of("Hamza","Yassmine","Aicha").forEach(name->{
                Customer customer=new Customer();
                customer.setName(name);
                customer.setEmail(name+"@gmail.com");
                // customer.setPassword("1234");
                customerRepository.save(customer);
            });
			 customerRepository.findAll().forEach(cust->{
                CurrentAccount currentAccount=new CurrentAccount();
                currentAccount.setId(UUID.randomUUID().toString());
                currentAccount.setBalance(Math.random()*90000);
                currentAccount.setCreatedAt(new Date(0));
                currentAccount.setStatus(AccountStatus.CREATED);
                currentAccount.setCustomer(cust);
                currentAccount.setOverDraft(9000);
                bankAccountRepository.save(currentAccount);

                SavingAccount savingAccount=new SavingAccount();
                savingAccount.setId(UUID.randomUUID().toString());
                savingAccount.setBalance(Math.random()*90000);
                savingAccount.setCreatedAt(new Date(0));
                savingAccount.setStatus(AccountStatus.CREATED);
                savingAccount.setCustomer(cust);
                savingAccount.setInterestRate(5.5);
                bankAccountRepository.save(savingAccount);

            });
			  bankAccountRepository.findAll().forEach(acc->{
                for (int i = 0; i <10 ; i++) {
                    AccountOperation accountOperation=new AccountOperation();
                    accountOperation.setOperationDate(new Date(i));
                    accountOperation.setAmount(Math.random()*12000);
                    accountOperation.setType(Math.random()>0.5? OperationType.DEBIT: OperationType.CREDIT);
                    accountOperation.setBankAccount(acc);
                    accountOperationRepository.save(accountOperation);
                }

            });
			
		};
	}

}
