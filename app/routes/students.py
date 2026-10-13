
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import require_role
from app.database import get_db
from app.models import Grade, User


router = APIRouter(prefix="/students", tags=["Students"])


@router.get("/me/grades")
def my_grades(
    current_user: User = Depends(require_role("student")),
    db: Session = Depends(get_db),
):
    """Студент бачить лише власні оцінки."""

    grades = (
        db.query(Grade)
        .filter(Grade.student_id == current_user.id)
        .all()
    )

    return {
        "student": current_user.username,
        "grades": [
            {
                "subject_id": grade.subject_id,
                "grade": grade.grade,
                "comment": grade.comment,
                "date": grade.date_assigned.isoformat(),
            }
            for grade in grades
        ],
    }
