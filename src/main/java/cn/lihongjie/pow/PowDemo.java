package cn.lihongjie.pow;

import cn.lihongjie.pow.client.PowChallengeSolver;
import cn.lihongjie.pow.core.PowChallengeGenerator;
import cn.lihongjie.pow.core.PowChallengeVerifier;
import cn.lihongjie.pow.model.PowChallenge;
import cn.lihongjie.pow.model.PowSolution;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JWT PoW 系统交互式 Demo
 * 
 * <p>演示完整流程：
 * <ol>
 *   <li>服务端生成挑战</li>
 *   <li>客户端求解</li>
 *   <li>服务端验证</li>
 * </ol>
 * 
 * @author lihongjie
 */
public class PowDemo {
    
    private static final Logger log = LoggerFactory.getLogger(PowDemo.class);
    
    private static final String SECRET_KEY = "ThisIsAVerySecureSecretKeyWith256Bits!!";

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║         JWT Proof-of-Work Challenge System Demo         ║");
        System.out.println("║                  Author: lihongjie                       ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println();
        
        // 初始化组件
        PowChallengeGenerator generator = new PowChallengeGenerator(SECRET_KEY);
        PowChallengeVerifier verifier = new PowChallengeVerifier(
                SECRET_KEY, 
                new SimpleReplayProtection()
        );
        PowChallengeSolver solver = new PowChallengeSolver();
        
        Scanner scanner = new Scanner(System.in);
        
        while (true) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("请选择难度级别（或输入 'q' 退出）：");
            System.out.println("  1. 简单    (Difficulty = 100,     预计 < 1ms)");
            System.out.println("  2. 中等    (Difficulty = 1,000,   预计 ~10ms)");
            System.out.println("  3. 困难    (Difficulty = 10,000,  预计 ~100ms)");
            System.out.println("  4. 极难    (Difficulty = 100,000, 预计 ~1s)");
            System.out.println("  5. 自定义难度");
            System.out.print("\n选择: ");
            
            String input = scanner.nextLine().trim();
            
            if (input.equalsIgnoreCase("q")) {
                System.out.println("\n再见！");
                break;
            }
            
            double difficulty;
            
            try {
                switch (input) {
                    case "1":
                        difficulty = 100;
                        break;
                    case "2":
                        difficulty = 1000;
                        break;
                    case "3":
                        difficulty = 10000;
                        break;
                    case "4":
                        difficulty = 100000;
                        break;
                    case "5":
                        System.out.print("输入自定义难度因子 (>= 1.0): ");
                        difficulty = Double.parseDouble(scanner.nextLine().trim());
                        if (difficulty < 1.0) {
                            System.out.println("❌ 难度必须 >= 1.0");
                            continue;
                        }
                        break;
                    default:
                        System.out.println("❌ 无效选择");
                        continue;
                }
            } catch (Exception e) {
                System.out.println("❌ 输入错误：" + e.getMessage());
                continue;
            }
            
            System.out.println("\n" + "-".repeat(60));
            System.out.println("🚀 开始挑战流程 [Difficulty = " + difficulty + "]");
            System.out.println("-".repeat(60));
            
            try {
                // === 阶段 1: 服务端生成挑战 ===
                System.out.println("\n[Phase 1] 🔧 服务端生成挑战...");
                long genStart = System.nanoTime();
                
                PowChallenge challenge = generator.generate(difficulty);
                
                long genTime = (System.nanoTime() - genStart) / 1_000; // 微秒
                
                System.out.println("  ✓ 生成完成 (耗时: " + genTime + "μs)");
                System.out.println("  • JTI:    " + challenge.getJwtId());
                System.out.println("  • Salt:   " + challenge.getSalt());
                System.out.println("  • Target: " + challenge.getTargetHex().substring(0, 32) + "...");
                System.out.println("  • Token:  " + challenge.getToken().substring(0, 50) + "...");
                
                // === 阶段 2: 客户端求解 ===
                System.out.println("\n[Phase 2] 🔨 客户端求解中...");
                long solveStart = System.currentTimeMillis();
                
                PowSolution solution = solver.solve(challenge.getToken(), 100_000_000L);
                
                long solveTime = System.currentTimeMillis() - solveStart;
                
                System.out.println("  ✓ 求解成功 (耗时: " + solveTime + "ms)");
                System.out.println("  • Nonce:    " + solution.getNonce());
                System.out.println("  • Attempts: " + solution.getAttempts());
                
                if (solveTime > 0) {
                    double hashrate = solution.getAttempts() / (solveTime / 1000.0);
                    System.out.println("  • Hashrate: " + String.format("%.2f", hashrate) + " H/s");
                }
                
                // === 阶段 3: 服务端验证 ===
                System.out.println("\n[Phase 3] ✅ 服务端验证中...");
                long verifyStart = System.nanoTime();
                
                boolean valid = verifier.verify(solution);
                
                long verifyTime = (System.nanoTime() - verifyStart) / 1_000; // 微秒
                
                if (valid) {
                    System.out.println("  ✓ 验证通过 (耗时: " + verifyTime + "μs)");
                    System.out.println("\n🎉 挑战成功完成！");
                } else {
                    System.out.println("  ✗ 验证失败 (耗时: " + verifyTime + "μs)");
                    System.out.println("\n❌ 挑战失败！");
                }
                
                // === 性能总结 ===
                System.out.println("\n📊 性能统计：");
                System.out.println("  生成延迟:   " + genTime + " μs");
                System.out.println("  求解时间:   " + solveTime + " ms");
                System.out.println("  验证延迟:   " + verifyTime + " μs");
                System.out.println("  总耗时:     " + (solveTime + (genTime + verifyTime) / 1000) + " ms");
                System.out.println("  验证/求解比: 1 : " + 
                        String.format("%.0f", (solveTime * 1000.0) / verifyTime));
                
            } catch (Exception e) {
                log.error("Demo execution error", e);
                System.out.println("\n❌ 错误：" + e.getMessage());
            }
        }
        
        scanner.close();
    }

    /**
     * 简单的内存防重放实现（仅用于 Demo）
     */
    static class SimpleReplayProtection implements PowChallengeVerifier.ReplayProtection {
        
        private final Set<String> usedJtis = ConcurrentHashMap.newKeySet();

        @Override
        public boolean isUsed(String jti) {
            return usedJtis.contains(jti);
        }

        @Override
        public void markAsUsed(String jti, long expiration) {
            usedJtis.add(jti);
        }
    }
}
