package com.ebanking_backs.ebanking_backs.entities;

// import java.sql.Date;
import java.util.Date;


import com.ebanking_backs.ebanking_backs.enums.OperationType;
import jakarta.persistence.*;
import lombok.*;


@Entity
@Data @NoArgsConstructor @AllArgsConstructor
public class AccountOperation {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Date operationDate;
    private double amount;
    @Enumerated(EnumType.STRING)
    private OperationType type;
    @ManyToOne
    private BankAccount bankAccount;
    private String description;
}
