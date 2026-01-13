package cn.lihongjie.pow.model;

/**
 * PoW 挑战的解决方案
 * 
 * @author lihongjie
 */
public class PowSolution {
    
    /**
     * 原始 JWT Token
     */
    private final String token;
    
    /**
     * 找到的 Nonce 值（穷举结果）
     */
    private final long nonce;
    
    /**
     * 尝试次数（穷举了多少次）
     */
    private final long attempts;
    
    /**
     * 耗时（毫秒）
     */
    private final long timeMillis;

    public PowSolution(String token, long nonce, long attempts, long timeMillis) {
        this.token = token;
        this.nonce = nonce;
        this.attempts = attempts;
        this.timeMillis = timeMillis;
    }

    public String getToken() {
        return token;
    }

    public long getNonce() {
        return nonce;
    }

    public long getAttempts() {
        return attempts;
    }

    public long getTimeMillis() {
        return timeMillis;
    }

    @Override
    public String toString() {
        return "PowSolution{" +
                "token='" + token + '\'' +
                ", nonce=" + nonce +
                ", attempts=" + attempts +
                ", time=" + timeMillis + "ms" +
                '}';
    }
}
