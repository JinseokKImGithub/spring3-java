package com.security.study.config.advices;

import java.io.IOException;

public class CustomException extends RuntimeException {

    public CustomException(IOException msg) {
        super(msg);
    }
}
