package com.security.study.config.advices;

import lombok.Getter;

@Getter
public class ApplicationException extends RuntimeException{
    private final ErrorCode errorCode;
    private final String message;

    public ApplicationException(ErrorCode enumErrorCode){
        this.errorCode = enumErrorCode;
        this.message = enumErrorCode.getMessage();
    }
}

