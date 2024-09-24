package com.ebanking_backs.ebanking_backs.entities;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
// import jakarta.persistence.*;
import lombok.*;

@EqualsAndHashCode(callSuper = true)

@Entity
@DiscriminatorValue("SA")
@Data @NoArgsConstructor @AllArgsConstructor
public class SavingAccount extends BankAccount {
    private double interestRate;
}
