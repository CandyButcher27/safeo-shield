"""Tests for local vLLM llm_guard (no GPU required)."""
import os
import unittest
from unittest.mock import MagicMock, patch

# Disable LLM by default in tests unless explicitly enabled
os.environ.setdefault("SECUREC_ENABLE_LLM_AUGMENTATION", "true")

from safeo_backend.core.ml import llm_guard
from safeo_backend.core.ml import tiered_llm


class TestLlmGuard(unittest.TestCase):
    def test_is_llm_available_returns_bool(self):
        with patch("safeo_backend.core.ml.llm_guard.requests.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200)
            self.assertTrue(llm_guard.is_llm_available())
            self.assertIsInstance(llm_guard.is_llm_available(), bool)

        with patch("safeo_backend.core.ml.llm_guard.requests.get", side_effect=OSError("offline")):
            self.assertFalse(llm_guard.is_llm_available())

    def test_fallback_when_vllm_offline(self):
        with patch("safeo_backend.core.ml.llm_guard.is_llm_available", return_value=False):
            result = llm_guard.analyze("DROP TABLE users", {})
        self.assertEqual(result["llm_score"], 0.5)
        self.assertIn("unavailable", result["explanation"].lower())
        self.assertTrue(result.get("fallback"))
        self.assertIn("inference_ms", result)

    def test_analyze_with_mock_openai_client(self):
        mock_completion = MagicMock()
        mock_completion.choices = [
            MagicMock(
                message=MagicMock(
                    content='{"risk_score": 0.91, "attack_type": "sql_injection", "explanation": "malicious"}'
                )
            )
        ]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_completion

        with patch("safeo_backend.core.ml.llm_guard.is_llm_available", return_value=True):
            with patch("openai.OpenAI", return_value=mock_client):
                tiered_llm._llm_call_count = 0
                result = llm_guard.analyze("' OR 1=1", {})
        self.assertGreaterEqual(result["llm_score"], 0.9)
        self.assertFalse(result.get("fallback"))
        self.assertGreaterEqual(tiered_llm.get_llm_call_count(), 1)


if __name__ == "__main__":
    unittest.main()
