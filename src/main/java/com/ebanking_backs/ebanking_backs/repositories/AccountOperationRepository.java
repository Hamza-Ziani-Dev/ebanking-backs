package com.ebanking_backs.ebanking_backs.repositories;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.JpaRepository;

import com.ebanking_backs.ebanking_backs.entities.AccountOperation;



public interface AccountOperationRepository extends JpaRepository<AccountOperation,Long> {
  List<AccountOperation> findByBankAccountId(String accountId);
  Page<AccountOperation> findByBankAccountIdOrderByOperationDateDesc(String accountId, Pageable pageable);
}
