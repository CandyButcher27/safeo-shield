"""Tests for MultilingualAgent (model mocked — no GPU)."""
import unittest

from safeo_backend.agents.multilingual_agent import MultilingualAgent


class TestMultilingualAgent(unittest.TestCase):
    def setUp(self):
        MultilingualAgent._load_attempted = True
        MultilingualAgent._model = None
        MultilingualAgent._tokenizer = None
        MultilingualAgent._ref_embeddings = None
        MultilingualAgent._script_history.clear()
        MultilingualAgent._script_counts.clear()
        MultilingualAgent._evasion_attempts = 0
        MultilingualAgent._inference_ms_total = 0.0
        MultilingualAgent._inference_n = 0
        self.agent = MultilingualAgent()

    def test_urdu_sqli_flags_evasion(self):
        text = "انتخاب ۱ یا ۱=۱"
        ev = self.agent.score_evasion(text)
        self.assertTrue(ev["evasion_suspected"])
        out = self.agent.analyse(text)
        self.assertTrue(out["evasion_suspected"])
        self.assertIn(out["script_detected"], ("urdu", "arabic", "mixed"))

    def test_arabic_xss_mixed_script(self):
        text = "<script>alert('مرحبا')</script>"
        script = self.agent.detect_script(text)
        self.assertIn(script, ("mixed", "latin", "arabic"))

    def test_clean_urdu_not_evasion(self):
        text = "یہ ایک معمولی کاروباری نوٹ ہے۔"
        ev = self.agent.score_evasion(text)
        self.assertFalse(ev["evasion_suspected"])


if __name__ == "__main__":
    unittest.main()
