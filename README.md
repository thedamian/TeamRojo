
<div align="center">
 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥 🔥

# Team ROJO 🔥 🔥 🔥

**A LLM Red Team Testing App**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

<p align="center">
  <br>
  <b>Test your AI endpoints for Prompt Injection vulnerabilities with style!</b>
  <br>
</p>

</div>

---

## 🧐 What is Team Rojo?

**Team Rojo** is a hot 🔥 new interactive Red Teaming agent designed to test any OpenAI-compatible endpoint. It wraps powerful security tools in a sleek, retro-CLI interface complete with real-time animations.

It combines the power of **HiddenLayer** and **PyRit** to simulate adversarial attacks against your LLM applications, ensuring they are robust enough to handle the heat!

## ✨ Features

*   **🔥 Real-time Fire Animation:** A dynamic, full-screen ASCII fire background that intensifies when tests are running.
*   **🖥️ Retro CLI Interface:** A clean, hacker-style web UI for easy interaction.
*   **🤖 Dual-Engine Testing:** leverages both `hiddenlayer-sdk` and `pyrit` for comprehensive coverage.
*   **📡 WebSocket Streaming:** Watch the attack logs stream in real-time as the agent probes your model.
*   **📄 PDF Reports:** Export professional reports of your security posture with a single click. (Includes a big green "Success" stamp if you pass!)
*   **🎯 Target Agnostic:** Works with any OpenAI-compatible API (OpenAI, Azure OpenAI, Local LLMs).

---

## 🚀 Quick Start

### Prerequisites

*   Python 3.12+
*   [`uv`](https://github.com/astral-sh/uv) (Recommended) or standard `pip`

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/team-rojo.git
    cd team-rojo
    ```

2.  **Install dependencies:**
    ```bash
    # Using uv (faster!)
    uv sync
    
    # OR using pip
    pip install -r requirements.txt
    ```

### Running the App

Ignite the engine! 🏎️💨

```bash
uv run uvicorn teamRojo:app --reload
```

Then open your browser and head to: **`http://127.0.0.1:8000`**

---

## 🎮 How to Use

1.  **Enter Target:** Input your Base URL (e.g., `https://api.openai.com/v1`).
2.  **Select Model:** Choose the model ID you want to test (e.g., `gpt-5-mini`).
3.  **Authenticate:** Provide your API Key.
4.  **CLICK "RED TEAM THIS!":**
    *   Watch the fire roar! 🔥
    *   Observe the logs as the agent attempts injection attacks.
5.  **Analyze & Export:** Once finished, download the PDF report to share with your team.

---

## 🛠️ Built With

*   **FastAPI:** High-performance backend.
*   **WebSockets:** For that sweet real-time data flow.
*   **JavaScript (Vanilla):** For the custom ASCII rendering engine.
*   **HiddenLayer SDK:** Enterprise-grade security scanning.
*   **PyRit:** The Python Risk Identification Tool for generative AI.

---

## ⚠️ Disclaimer

*This tool is for educational and authorized security testing purposes only. Always ensure you have permission to test the target endpoints.*

<div align="center">
  <sub>Made with ❤️ and a lot of ☕ by Team Rojo</sub>
</div>
