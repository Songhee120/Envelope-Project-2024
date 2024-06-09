package com.webcode.detectiveclub.controller;

import com.webcode.detectiveclub.service.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
public class HomeController {


    @Autowired
    private Service service;

    // TODO: message 입력 받는걸로 변경
    private static String message = "안녕하세요.";

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("users", service.getUsers());
        return "index";
    }

    @PostMapping("/envelope")
    public String envelope(@RequestParam("sender") String sender, @RequestParam("receiver") String receiver, Model model) {
        service.setSender(sender);
        service.setReceiver(receiver);
        service.setMessage(message);

        model.addAttribute("sender", sender);
        model.addAttribute("receiver", receiver);
        return "envelope";
    }

    @PostMapping("/step1")
    @ResponseBody
    public Map<String, String> step1() {
//        sendingService.generateKeyPair(sendingService.getSender());
//        sendingService.generateKeyPair(sendingService.getReceiver());
//        sendingService.generateSecretKey(sendingService.getSender());

        Map<String, String> response = new HashMap<>();
        response.put("step1Output", "완료!");
        return response;
    }

    @PostMapping("/step2")
    @ResponseBody
    public Map<String, String> step2() {
        Map<String, String> response = new HashMap<>();

//        // 메세지 해시값을 개인키로 암호화 후 파일 저장
//        sendingService.generateSignature(sendingService.getHashValue(message));
//
//        // 메세지, 전자서명, 공개키를 비밀키로 암호화
//        sendingService.encryptWithPrivateKey();

        response.put("step2Output", "완료!");
        return response;
    }

    @PostMapping("/step3")
    @ResponseBody
    public Map<String, String> step3() {
        Map<String, String> response = new HashMap<>();

        // 비밀키를 수신자 공개키로 암호화
//        sendingService.generateEnvelope();

        response.put("step3Output", "완료!");
        return response;
    }

    @GetMapping("/result")
    public String result(Model model) {
        // 비밀키 구해서 메세지 내용, 전자서명, 수신자 공개키 복호화 후, 메세지 리턴
        service.decryptAllAndGetMessage();

        return "result";
    }

    @GetMapping("/check")
    public Map<String, String> check() {
        // 전자서명 복호화한 해시값 | 메세지의 해시값 비교


        return null;
    }



    
}
