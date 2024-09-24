package com.ebanking_backs.ebanking_backs.dtos;
// import java.sql.Date;
import java.util.Date;

import com.ebanking_backs.ebanking_backs.enums.OperationType;

import lombok.Data;


@Data
public class AccountOperationDTO {
    private Long id;
    private Date operationDate;
    private double amount;
    private OperationType type;
    private String description;
}
