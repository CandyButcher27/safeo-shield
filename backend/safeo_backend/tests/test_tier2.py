"""
Tests for Tier-2 classifier and tier routing logic.
The distilBERT model is mocked — only routing and fallback logic is tested.
"""
import types
import unittest
from unittest.mock import MagicMock, patch


class TestTier2TFIDFFallback(unittest.TestCase):
    """Test TF-IDF fallback classifier without any torch dependency."""

    def _make_classifier(self):
        """Build a Tier2Classifier that goes straight to the fallback."""
        from safeo_backend.core.ml.tier2_classifier import Tier2Classifier
        clf = object.__new__(Tier2Classifier)
        clf._model = None
        clf._tokenizer = None
        clf._device = "cpu"
        clf._ready = False
        clf._fallback_pipeline = None
        clf._load_fallback()
        return clf

    def test_threat_detected(self):
        clf = self._make_classifier()
        result = clf.classify("' OR 1=1 --")
        self.assertIn("tier2_score", result)
        self.assertIn("label", result)
        self.assertIn("confidence", result)
        self.assertGreaterEqual(result["tier2_score"], 0.5, "SQLi should be flagged as threat")

    def test_safe_text(self):
        clf = self._make_classifier()
        result = clf.classify("Please process the invoice for Q3 vendor payment")
        self.assertLess(result["tier2_score"], 0.7, "Clean text should not score high threat")

    def test_inference_ms_present(self):
        clf = self._make_classifier()
        result = clf.classify("test input")
        self.assertIn("inference_ms", result)
        self.assertGreaterEqual(result["inference_ms"], 0)


class TestTierRouting(unittest.TestCase):
    """Test the tier routing decision function (llm_guard mocked out)."""

    def _route(self, score, text="test"):
        # Mock llm_guard so we don't need 'requests' installed
        fake_guard = types.ModuleType("safeo_backend.core.ml.llm_guard")
        fake_guard.is_llm_available = lambda: False
        fake_guard.llm_enabled = lambda: False
        with patch.dict("sys.modules", {"safeo_backend.core.ml.llm_guard": fake_guard}):
            # Remove cached module if already imported
            import sys
            for k in list(sys.modules):
                if "tiered_llm" in k:
                    del sys.modules[k]
            from safeo_backend.core.ml.tiered_llm import run_tiered_scoring
            return run_tiered_scoring(score, [], text)

    def test_tier1_low(self):
        adjusted, tier, meta = self._route(0.10)
        self.assertEqual(tier, 1)

    def test_tier1_high(self):
        adjusted, tier, meta = self._route(0.80)
        self.assertEqual(tier, 1)

    def test_tier2_band_with_fallback(self):
        """In uncertain band 0.35-0.65 tier-2 TF-IDF (no bert) should resolve."""
        adjusted, tier, meta = self._route(0.50, "approve the invoice for the Q3 vendor")
        self.assertIn(tier, (1, 2), "Should resolve at tier 1 or 2 (no LLM)")
        self.assertGreaterEqual(adjusted, 0.0)
        self.assertLessEqual(adjusted, 1.0)


class TestTierStats(unittest.TestCase):
    def test_reset_and_record(self):
        from safeo_backend.utils.tier_stats import reset_stats, record, get_stats
        reset_stats()
        record(1)
        record(1)
        record(2)
        record(3)
        s = get_stats()
        self.assertEqual(s["tier1_decisions"], 2)
        self.assertEqual(s["tier2_decisions"], 1)
        self.assertEqual(s["tier3_decisions"], 1)
        self.assertEqual(s["total_requests"], 4)
        self.assertEqual(s["llm_calls_saved"], 3)

    def test_llm_savings_pct(self):
        from safeo_backend.utils.tier_stats import reset_stats, record, get_stats
        reset_stats()
        for _ in range(80):
            record(1)
        for _ in range(20):
            record(3)
        s = get_stats()
        self.assertAlmostEqual(s["llm_savings_pct"], 80.0)


if __name__ == "__main__":
    unittest.main()
