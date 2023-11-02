package com.security.study.config.advices;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;
@Getter
@AllArgsConstructor
public enum ErrorCode {

    /**
     * ******************************* Global Error CodeList ***************************************
     * HTTP Status Code
     * 400 : Bad Request
     * 401 : Unauthorized
     * 403 : Forbidden
     * 404 : Not Found
     * 500 : Internal Server Error
     * *********************************************************************************************
     */
    // 잘못된 서버 요청
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "토근 유효기간 만료"),
    INVALID_TOKEN(HttpStatus.FORBIDDEN, "유효하지 않은 토큰"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "잘못된 요청"),
    NOT_FOUND(HttpStatus.NOT_FOUND, "없는 데이터"),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "없는 유저"),
    LOGIN_ERROR(HttpStatus.BAD_REQUEST, "로그인 오류"),
    UNAUTHORIZED(HttpStatus.NOT_FOUND, "권한 없음"),
    FORBIDDEN(HttpStatus.NOT_FOUND, "접근 금지"),
    DUPLICATED_USER_EMAIL(HttpStatus.BAD_REQUEST, "이메일 중복"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error"),

;
    /**
     * ******************************* Error Code Constructor ***************************************
     */
    // 에러 코드의 '코드 상태'을 반환한다.
    private final HttpStatus httpStatus;

    // 에러 코드의 '코드 메시지'을 반환한다.
    private final String message;

}
