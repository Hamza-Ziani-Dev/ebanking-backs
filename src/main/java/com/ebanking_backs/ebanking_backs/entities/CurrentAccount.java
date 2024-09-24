package com.ebanking_backs.ebanking_backs.entities;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
// import jakarta.persistence.*;
import lombok.*;

@EqualsAndHashCode(callSuper = true)
 @Entity
 @DiscriminatorValue("CA")
 @Data @NoArgsConstructor @AllArgsConstructor
 public class CurrentAccount extends BankAccount {
     private double overDraft;
 }
