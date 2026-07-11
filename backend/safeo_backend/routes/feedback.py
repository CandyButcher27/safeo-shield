"""Simple in-memory feedback endpoint (optional judge / tester notes)."""
from fastapi import APIRouter
from ..models.schemas import FeedbackRequest

router = APIRouter(prefix="/feedback", tags=["Feedback"])
_store = []


@router.post("/")
async def submit_feedback(req: FeedbackRequest):
    _store.append(req.model_dump())
    return {"status": "accepted", "total_feedback": len(_store)}


@router.get("/")
async def list_feedback():
    return {"feedback": _store}
