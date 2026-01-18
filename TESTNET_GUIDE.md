# Testnet Integration Testing Guide

本指南说明如何为钱包核心库获取测试网代币并运行集成测试。

## ⚠️ 重要提示

**永远不要在主网上使用测试助记词！**

测试助记词：
```
steak treat wait fog two seven pluck sting wife motor machine topic image humor tobacco noodle seven mail staff century swim mimic now february
```

此助记词仅用于测试网测试，已公开在代码库中，请勿用于任何生产环境。

---

## 📋 测试钱包地址

所有地址都是从上述助记词派生的：

### 📗 EVM 兼容链（Ethereum、BSC、Polygon）
**地址**: `0xf741e62a73faa39fab126545e78c20789b0efe3e`

### 🟠 Bitcoin Testnet
**地址**: `bc1q6uj9uflfhrej2hlerkrws8d69xxjcssy50gzqs`

### 🟣 Solana Devnet
**地址**: `GJ7TtwSH8UAcxgFj5jfbpz27gbPtxyLLxvqVUUikT4UJ`

### ⚫ Aptos Devnet
**地址**: `0xa643ec826a43f4e5ce45e985c017ef0a5559d67aea4525d5320f839a5ad1fbdb`

### 🔵 Sui Devnet
**地址**: `0xf18c5e78fe1477ecd7994355614947d6940d0720a19265f5da981f85e9aa0043`

### 🔴 TRON Nile Testnet
**地址**: `TS2xgUr4gVg25gciBMbwYm2yQa9nusgJX5`

### 💎 TON Testnet
**地址**: `EQCzeTi8pTUYR_34GKyYyjioAXlFMMjfjKFW9BMbdRFvHzwA`

### ⚪ NEAR Testnet
**地址**: `cdf9c010ee9b7702944c81ac88df979efcb7cf3e70e7f082c7047a004ddcdb7f`

### ⚡ Filecoin Calibration
**地址**: `f1njwnndkxrwsvlpeyzr4a5s4asrwjsd3rde6573q`

---

## 🚰 如何领取测试币

### 1️⃣ EVM 链（Ethereum Sepolia、BSC、Polygon）

#### Ethereum Sepolia
- **Alchemy Faucet**: https://sepoliafaucet.com/
  - 需要 Alchemy 账号
  - 每 24 小时领取 0.5 SepoliaETH

- **Infura Faucet**: https://www.infura.io/faucet/sepolia
  - 需要 Infura 账号
  - 每天 0.5 SepoliaETH

#### BSC Testnet
- **官方水龙头**: https://testnet.bnbchain.org/faucet-smart
  - 需要 BNB Chain 钱包扩展或 GitHub 登录
  - 每 24 小时领取 0.5 tBNB

#### Polygon Mumbai
- **官方水龙头**: https://faucet.polygon.technology/
  - 需要钱包连接
  - 每天 0.5 MATIC

---

### 2️⃣ Bitcoin Testnet

- **Mempool Faucet**: https://testnet-faucet.mempool.co/
  - 简单易用，无需登录
  - 直接输入地址领取

- **Bitcoin Faucet**: https://bitcoinfaucet.uo1.net/
  - 备用水龙头
  - 每次领取 ~0.01 tBTC

---

### 3️⃣ Solana Devnet

#### Web 水龙头
- **官方水龙头**: https://faucet.solana.com/
  - 输入地址
  - 可选择领取 1-5 SOL

#### CLI 命令
```bash
solana airdrop 2 GJ7TtwSH8UAcxgFj5jfbpz27gbPtxyLLxvqVUUikT4UJ --url devnet
```

---

### 4️⃣ Aptos Devnet

#### Web 水龙头
- **官方水龙头**: https://aptoslabs.com/testnet-faucet
  - 输入地址领取 1 APT

#### CLI 命令
```bash
aptos account fund-with-faucet \
  --account 0xa643ec826a43f4e5ce45e985c017ef0a5559d67aea4525d5320f839a5ad1fbdb \
  --network devnet
```

---

### 5️⃣ Sui Devnet

#### Discord 水龙头（推荐）
1. 加入 Sui Discord: https://discord.gg/sui
2. 前往 `#devnet-faucet` 频道
3. 发送命令：
   ```
   !faucet 0xf18c5e78fe1477ecd7994355614947d6940d0720a19265f5da981f85e9aa0043
   ```

#### CLI 命令
```bash
sui client faucet --address 0xf18c5e78fe1477ecd7994355614947d6940d0720a19265f5da981f85e9aa0043
```

---

### 6️⃣ TRON Nile Testnet

- **Nile Faucet**: https://nileex.io/join/getJoinPage
  - 需要 TronLink 钱包扩展
  - 每天领取 10,000 TRX

- **Shasta Testnet**: https://www.trongrid.io/shasta/
  - 备用测试网
  - 每天 10,000 TRX

---

### 7️⃣ TON Testnet

#### Telegram Bot（推荐）
1. 打开 Telegram
2. 访问: https://t.me/testgiver_ton_bot
3. 发送钱包地址：`EQCzeTi8pTUYR_34GKyYyjioAXlFMMjfjKFW9BMbdRFvHzwA`

#### Web 水龙头
- https://ton.org/testnet
- 需要连接 TON 钱包

---

### 8️⃣ NEAR Testnet

#### Web 水龙头
- **NEAR Faucet**: https://near-faucet.io/
  - 输入隐式地址
  - 领取 200 NEAR

#### 创建钱包（获得 200 NEAR）
1. 访问: https://testnet.mynearwallet.com/
2. 创建新钱包
3. 导入测试助记词
4. 自动获得 200 NEAR

---

### 9️⃣ Filecoin Calibration Testnet

- **官方水龙头**: https://faucet.calibration.fildev.network/
  - 输入地址：`f1njwnndkxrwsvlpeyzr4a5s4asrwjsd3rde6573q`
  - 每 24 小时领取 100 tFIL

---

## 🧪 运行集成测试

### 1. 确保所有地址都有测试币

按照上述指南为每条链领取测试币。

### 2. 设置环境变量（可选）

如果需要使用自定义 RPC 端点：

```bash
export SEPOLIA_RPC="https://your-custom-rpc.com"
export SOLANA_RPC="https://your-custom-rpc.com"
# ... 其他链的 RPC
```

### 3. 运行集成测试

```bash
# 运行所有集成测试
npm run test:integration

# 运行特定链的集成测试
npm test src/test/integration/evm-integration.test.ts
npm test src/test/integration/solana-integration.test.ts
```

### 4. 跳过集成测试（CI/CD）

集成测试默认在 CI 环境中跳过，如需运行：

```bash
RUN_INTEGRATION=true npm test
```

---

## 📊 检查余额

### 使用区块链浏览器

#### Ethereum Sepolia
https://sepolia.etherscan.io/address/0xf741e62a73faa39fab126545e78c20789b0efe3e

#### Bitcoin Testnet
https://blockstream.info/testnet/address/bc1q6uj9uflfhrej2hlerkrws8d69xxjcssy50gzqs

#### Solana Devnet
https://explorer.solana.com/address/GJ7TtwSH8UAcxgFj5jfbpz27gbPtxyLLxvqVUUikT4UJ?cluster=devnet

#### Aptos Devnet
https://explorer.aptoslabs.com/account/0xa643ec826a43f4e5ce45e985c017ef0a5559d67aea4525d5320f839a5ad1fbdb?network=devnet

#### Sui Devnet
https://suiscan.xyz/devnet/account/0xf18c5e78fe1477ecd7994355614947d6940d0720a19265f5da981f85e9aa0043

#### TRON Nile
https://nile.tronscan.org/#/address/TS2xgUr4gVg25gciBMbwYm2yQa9nusgJX5

#### TON Testnet
https://testnet.tonscan.org/address/EQCzeTi8pTUYR_34GKyYyjioAXlFMMjfjKFW9BMbdRFvHzwA

#### Filecoin Calibration
https://calibration.filfox.info/en/address/f1njwnndkxrwsvlpeyzr4a5s4asrwjsd3rde6573q

---

## 🔐 安全注意事项

1. ✅ 此助记词**仅用于测试网**
2. ❌ **永远不要**将真实资金发送到这些地址
3. ❌ **永远不要**在主网上使用此助记词
4. ✅ 测试币没有真实价值
5. ✅ 可以安全地公开这些地址和助记词

---

## 📝 维护说明

### 定期检查水龙头状态
- 有些水龙头可能会失效或更改 URL
- 定期更新此文档中的链接
- 测试所有水龙头是否正常工作

### 更新 RPC 端点
- 公共 RPC 可能有速率限制
- 考虑使用 Alchemy、Infura、QuickNode 等服务
- 在 `testnet-config.ts` 中更新 RPC URLs

---

## 🤝 贡献

如果发现更好的水龙头或 RPC 端点，欢迎提交 PR 更新此文档！
