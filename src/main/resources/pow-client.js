/**
 * JavaScript PoW Challenge Solver (Browser Compatible)
 * 
 * 使用 Web Crypto API 实现高性能哈希计算
 * 支持 Web Worker 多线程加速
 * 
 * @author lihongjie
 */

/**
 * 单线程 PoW 求解器
 * 
 * @param {string} token - JWT Token
 * @param {number} maxAttempts - 最大尝试次数
 * @returns {Promise<number>} - 找到的 Nonce（-1 表示失败）
 */
async function solvePowChallenge(token, maxAttempts = 100000000) {
    console.time('PoW Solving');
    
    // 1. 解析 JWT Payload
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }
    
    const payloadJson = atob(parts[1]);
    const payload = JSON.parse(payloadJson);
    const targetHex = payload.tgt;
    
    if (!targetHex || targetHex.length !== 64) {
        throw new Error('Invalid target hex in JWT payload');
    }
    
    console.log(`🎯 Target: ${targetHex.substring(0, 32)}...`);
    console.log(`🔨 Starting brute force (max: ${maxAttempts.toLocaleString()} attempts)...`);
    
    const targetBytes = hexToBytes(targetHex);
    const encoder = new TextEncoder();
    
    // 2. 穷举求解
    for (let nonce = 0; nonce < maxAttempts; nonce++) {
        const input = token + nonce;
        const inputBytes = encoder.encode(input);
        
        // 计算 SHA-256
        const hashBuffer = await crypto.subtle.digest('SHA-256', inputBytes);
        const hashBytes = new Uint8Array(hashBuffer);
        
        // 比对哈希值
        if (compareByteArrays(hashBytes, targetBytes) < 0) {
            console.timeEnd('PoW Solving');
            console.log(`✅ Solution found! Nonce: ${nonce}`);
            console.log(`📊 Attempts: ${(nonce + 1).toLocaleString()}`);
            return nonce;
        }
        
        // 进度提示（每 10 万次）
        if (nonce > 0 && nonce % 100000 === 0) {
            console.log(`⏳ Progress: ${(nonce / 1000000).toFixed(1)}M attempts...`);
        }
    }
    
    console.timeEnd('PoW Solving');
    console.warn('❌ Failed to find solution within max attempts');
    return -1;
}

/**
 * Web Worker 多线程求解器
 * 
 * @param {string} token - JWT Token
 * @param {number} threadCount - 线程数（默认为 CPU 核心数）
 * @param {number} maxAttempts - 最大尝试次数
 * @returns {Promise<number>} - 找到的 Nonce
 */
async function solvePowChallengeMultiThreaded(token, threadCount = navigator.hardwareConcurrency || 4, maxAttempts = 100000000) {
    console.log(`🚀 Starting multi-threaded solving (${threadCount} threads)...`);
    console.time('Multi-threaded PoW Solving');
    
    const workerCode = `
        self.onmessage = async function(e) {
            const { token, startNonce, endNonce, targetHex } = e.data;
            
            const targetBytes = hexToBytes(targetHex);
            const encoder = new TextEncoder();
            
            for (let nonce = startNonce; nonce < endNonce; nonce++) {
                const input = token + nonce;
                const inputBytes = encoder.encode(input);
                const hashBuffer = await crypto.subtle.digest('SHA-256', inputBytes);
                const hashBytes = new Uint8Array(hashBuffer);
                
                if (compareByteArrays(hashBytes, targetBytes) < 0) {
                    self.postMessage({ found: true, nonce: nonce });
                    return;
                }
            }
            
            self.postMessage({ found: false, nonce: -1 });
        };
        
        function hexToBytes(hex) {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
            }
            return bytes;
        }
        
        function compareByteArrays(a, b) {
            const minLength = Math.min(a.length, b.length);
            for (let i = 0; i < minLength; i++) {
                if (a[i] < b[i]) return -1;
                if (a[i] > b[i]) return 1;
            }
            return a.length - b.length;
        }
    `;
    
    // 解析 Target
    const parts = token.split('.');
    const payloadJson = atob(parts[1]);
    const payload = JSON.parse(payloadJson);
    const targetHex = payload.tgt;
    
    // 创建 Worker Blob
    const blob = new Blob([workerCode], { type: 'application/javascript' });
    const workerUrl = URL.createObjectURL(blob);
    
    // 分配任务
    const workers = [];
    const rangePerThread = Math.floor(maxAttempts / threadCount);
    
    const results = await Promise.race(
        Array.from({ length: threadCount }, (_, i) => {
            return new Promise((resolve) => {
                const worker = new Worker(workerUrl);
                workers.push(worker);
                
                const startNonce = i * rangePerThread;
                const endNonce = (i === threadCount - 1) ? maxAttempts : (i + 1) * rangePerThread;
                
                worker.onmessage = (e) => {
                    if (e.data.found) {
                        console.timeEnd('Multi-threaded PoW Solving');
                        console.log(`✅ Solution found by worker ${i}! Nonce: ${e.data.nonce}`);
                        
                        // 终止所有 Worker
                        workers.forEach(w => w.terminate());
                        URL.revokeObjectURL(workerUrl);
                        
                        resolve(e.data.nonce);
                    } else if (i === threadCount - 1) {
                        // 最后一个 Worker 完成但未找到
                        resolve(-1);
                    }
                };
                
                worker.postMessage({ token, startNonce, endNonce, targetHex });
            });
        })
    );
    
    return results;
}

/**
 * 提交解决方案到服务端
 * 
 * @param {string} token - JWT Token
 * @param {number} nonce - 找到的 Nonce
 * @returns {Promise<boolean>} - 验证结果
 */
async function submitPowSolution(token, nonce) {
    const response = await fetch('/api/pow/verify', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token, nonce })
    });
    
    if (!response.ok) {
        throw new Error(`Verification failed: ${response.statusText}`);
    }
    
    const result = await response.json();
    return result.valid === true;
}

// ========== 工具函数 ==========

/**
 * 十六进制字符串转字节数组
 */
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * 字节数组比对（无符号）
 */
function compareByteArrays(a, b) {
    const minLength = Math.min(a.length, b.length);
    for (let i = 0; i < minLength; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return a.length - b.length;
}

// ========== 使用示例 ==========

/**
 * 完整流程示例
 */
async function exampleUsage() {
    try {
        // 1. 从服务端获取挑战
        const response = await fetch('/api/pow/challenge?difficulty=1000');
        const challenge = await response.json();
        const token = challenge.token;
        
        console.log('📥 Received challenge:', token);
        
        // 2. 求解挑战（选择单线程或多线程）
        const nonce = await solvePowChallenge(token);
        // const nonce = await solvePowChallengeMultiThreaded(token, 4);
        
        if (nonce < 0) {
            console.error('❌ Failed to solve PoW challenge');
            return;
        }
        
        // 3. 提交解决方案
        const valid = await submitPowSolution(token, nonce);
        
        if (valid) {
            console.log('🎉 PoW challenge passed! Proceeding with request...');
            // 执行实际的业务请求
        } else {
            console.error('❌ PoW verification failed');
        }
        
    } catch (error) {
        console.error('Error:', error);
    }
}

// ========== 浏览器集成 ==========

/**
 * 表单提交拦截器（防刷应用）
 */
function attachPowToForm(formId, apiEndpoint) {
    const form = document.getElementById(formId);
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton.textContent;
        
        try {
            // 禁用提交按钮
            submitButton.disabled = true;
            submitButton.textContent = '🔨 Solving PoW...';
            
            // 获取挑战
            const challengeResponse = await fetch(`${apiEndpoint}/challenge?difficulty=1000`);
            const challenge = await challengeResponse.json();
            
            // 求解
            const nonce = await solvePowChallenge(challenge.token);
            
            if (nonce < 0) {
                alert('Failed to solve PoW challenge. Please try again.');
                return;
            }
            
            // 添加 PoW 字段到表单
            const formData = new FormData(form);
            formData.append('pow_token', challenge.token);
            formData.append('pow_nonce', nonce);
            
            // 提交表单
            const response = await fetch(form.action, {
                method: form.method,
                body: formData
            });
            
            if (response.ok) {
                console.log('✅ Form submitted successfully');
                // 处理成功响应
            } else {
                console.error('❌ Form submission failed');
            }
            
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred. Please try again.');
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = originalText;
        }
    });
}

// 导出函数（ES6 模块）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        solvePowChallenge,
        solvePowChallengeMultiThreaded,
        submitPowSolution,
        attachPowToForm
    };
}
