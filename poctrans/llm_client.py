"""LLM Client - OpenAI 兼容 API 客户端。"""

import re
import json
import logging
from typing import List, Optional

from openai import OpenAI

from poctrans.config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_MAX_TOKENS

logger = logging.getLogger("poctrans")


def get_client() -> OpenAI:
    """获取 OpenAI 兼容客户端。"""
    return OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)


def chat(messages: List[dict], tools: Optional[List[dict]] = None,
         temperature: float = 0.0) -> dict:
    """发送聊天请求。

    Args:
        messages: 消息列表
        tools: 工具定义列表（function calling）
        temperature: 温度参数

    Returns:
        API 响应 message 对象
    """
    client = get_client()
    kwargs = {
        "model": LLM_MODEL,
        "messages": messages,
        "max_tokens": LLM_MAX_TOKENS,
        "temperature": temperature,
    }
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"

    response = client.chat.completions.create(**kwargs)
    return response.choices[0].message


def extract_code_block(text: str, language: str = "") -> Optional[str]:
    """从 LLM 输出中提取代码块。"""
    pattern = rf"```{language}\s*\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # 尝试不带语言标记的代码块
    pattern = r"```\s*\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return None
