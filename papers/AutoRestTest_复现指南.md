# AutoRestTest 论文复现指南

## 论文信息

- **标题**: A Multi-Agent Approach for REST API Testing with Semantic Graphs and LLM-Driven Inputs
- **作者**: Myeongsoo Kim, Tyler Stennett, Saurabh Sinha, Alessandro Orso
- **会议**: ICSE 2024 (International Conference on Software Engineering)
- **DOI**: https://doi.org/10.1145/3597503.3639109
- **arXiv**: https://arxiv.org/abs/2411.07098

## GitHub 仓库

- **地址**: https://github.com/selab-gatech/autoresttest
- **Stars**: 45 | **Forks**: 14
- **许可证**: MIT License
- **更新时间**: 2026年3月（活跃项目）

---

## 论文简介

本文提出了AutoRestTest，首个采用依赖嵌入多代理方法的REST API黑盒测试工具，整合了：
- 多代理强化学习（MARL）
- 语义属性依赖图（SPDG）
- 大型语言模型（LLM）

四个代理协同工作：API代理、依赖代理、参数代理、值代理。

---

## 复现思路

### 1. 环境准备

```bash
# 克隆仓库
git clone https://github.com/selab-gatech/autoresttest.git
cd autoresttest

# 创建虚拟环境 (需要 Python 3.10)
python3.10 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt
```

### 2. 配置LLM API

创建 `.env` 文件：

```bash
# 方式一：OpenAI API (推荐)
API_KEY='sk-xxxxxxx'

# 方式二：OpenRouter (部分免费)
OPENROUTER_API_KEY='sk-xxxxxxx'
```

**支持的所有Provider：**
- OpenAI (GPT-4o, GPT-4o-mini)
- OpenRouter
- Azure OpenAI
- 本地模型 (LocalAI, LM Studio, vLLM, Ollama)

### 3. 运行

```bash
# 交互式模式 (默认)
python -m autoresttest

# 快速配置模式
python -m autoresttest --quick

# 命令行指定配置
python -m autoresttest -s specs/petstore.yaml -t 300
```

参数说明：
- `-s, --spec PATH`: OpenAPI规范文件路径
- `-t, --time SECONDS`: 测试时长（秒）
- `--skip-wizard`: 跳过配置向导

### 4. 输出示例

程序运行时显示实时仪表盘：
- 操作覆盖率
- 状态码分布
- LLM调用成本
- 请求数量统计

---

## 成本参考

- 使用 GPT-4o-mini 测试约15个操作的API，成本约 **$0.1/次**
- 可通过OpenRouter使用免费额度测试

---

## 核心组件

| 代理 | 功能 |
|------|------|
| API代理 | 理解和探索API端点 |
| 依赖代理 | 学习API之间的依赖关系 |
| 参数代理 | 处理API参数 |
| 值代理 | 生成测试值（由LLM驱动） |

---

## 调优方向

- 调整Q学习参数（学习率、折扣因子、探索率）
- 更换LLM模型（GPT-4、Claude、本地Ollama）
- 修改测试时长
- 优化SPDG相似度算法

---

## 参考资料

- 演示视频: https://www.youtube.com/watch?v=VVus2W8rap8
- 项目文档: 参见 GitHub README.md

---

*整理时间: 2026-03-11*
