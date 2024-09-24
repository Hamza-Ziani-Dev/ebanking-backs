package com.ebanking_backs.ebanking_backs.dtos;

// import java.sql.Date;
import java.util.Date;

import com.ebanking_backs.ebanking_backs.enums.AccountStatus;
import lombok.Data;
import lombok.EqualsAndHashCode;
@EqualsAndHashCode(callSuper = true)

@Data
public class CurrentBankAccountDTO extends BankAccountDTO {
    private String id;
    private double balance;
    private Date createdAt;
    private AccountStatus status;
    private CustomerDTO customerDTO;
    private double overDraft;
}
