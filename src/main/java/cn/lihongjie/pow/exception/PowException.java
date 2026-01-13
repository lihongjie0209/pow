package cn.lihongjie.pow.exception;

/**
 * PoW 系统统一异常类
 * 
 * @author lihongjie
 */
public class PowException extends RuntimeException {
    
    public PowException(String message) {
        super(message);
    }
    
    public PowException(String message, Throwable cause) {
        super(message, cause);
    }
}
