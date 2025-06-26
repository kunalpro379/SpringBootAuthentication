package com.auth.dto;

public class MsgResponseDto {
     private String message;
     public MsgResponseDto(String message){
          this.message=message;
     }
     public String getMessage(){
          return message;
     }
     public void setMessage(String message){
          this.message=message;
     }
}
