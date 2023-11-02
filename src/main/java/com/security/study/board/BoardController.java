package com.security.study.board;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/board")
public class BoardController {

    @GetMapping
    public String getBoards() {
        return "board 도착";
    }
}
