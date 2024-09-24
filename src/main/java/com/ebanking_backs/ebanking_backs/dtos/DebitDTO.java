package com.ebanking_backs.ebanking_backs.dtos;

import lombok.Data;

@Data
public class DebitDTO {
    private String accountId;
    private double amount;
    private String description;


}
